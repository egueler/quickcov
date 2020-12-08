# QuickCov

This is a hacky solution for [Cupid](https://github.com/RUB-SysSec/cupid) (and another upcoming project), where we needed to extract branch coverage information for a huge number of files/runs, so it had to be as fast as possible.

The basic idea here is to instrument your binary with [AFL](https://github.com/google/AFL) (afl-gcc, etc.), and build AFL as a library to use it via a Python interface so you can quickly execute all corpus files and return branch coverage information (coverage over time, etc.).

This is just dirty research code - it's buggy and it's ugly -, so don't expect too much.

## Performance

If you're collecting the coverage information for a queue of 50 files on average, this is the expected performance on a `Intel Xeon Gold 6230 CPU @ 2.10GHz processors w/ 192GB RAM`:

```markdown
| mode          | time per file | files/s | time to cover 100,000 files |
|---------------|---------------|---------|-----------------------------|
| `AFL`         | 3.86ms        | 259     | 6m26s                       |
| `AFL_QEMU`    | 5.39ms        | 185     | 8m59s                       |
| `AFL_QEMU_BB` | 12.46ms       | 80      | 20m46s                      |
| `PTRACE`      | 100.42ms      | 10      | 2h47m22s                    | 
```

You can get 5x faster execution speeds if you decrease the bitmap size, [see section below](#even-faster).

## Build

```shell
$ # for QEMU support (it is required for the unittests):
$ (cd qemu_mode && ./build_qemu_support.sh)
$ # back in the root directory, let's build AFL and the python package:
$ ./build.sh
$ # make sure the package can be imported
$ python3 -c "import quickcov"
$ # let the unittest run
$ python3 -m pytest test.py -v -s 
```

## Example

You can use it from the command-line directly:

```shell
$ python3 quickcov/quickcov.py --corpus /dev/shm/corpus/ --plot out.json -- ./binary --flag @@
```

Which outputs the branch-coverage-over-time plot to out.json and prints the total number of visited branches to the console.

Or you can import and use it in Python like this:

```python
import quickcov
with quickcov.QuickCov("./binary", "--flag @@") as q:
    (plot, bitmap, final_coverage) = q.get_coverage("/dev/shm/fuzz/queue/")
```

`@@` is a wildcard for AFL to know where to insert the input file path in the argument list.

`get_coverage` accepts a number of parameters, as described in `quickcov.py`:

```python
def get_coverage(self, corpus, plot=False, \
                     time_dict=None, time_dict_lock=None, limit=None, \
                     relative_time=False, ignore_missing_files=True,
                     use_afl_file_filter=True, minimum_time=0)
```

* `corpus`: if string: directory where to find input files (e.g. `"/dev/shm/corpus/"`), if list: list of corpus files (absolute paths, e.g., `['/dev/shm/corpus/queue/id:00.txt', '/dev/shm/corpus/queue/id:01.txt']`)

* `plot`: set True if you want QuickCov to return a coverage-over-time plot

* `time_dict`: dictionary in a `{file: timestamp}` format to determine file creation times. You should use inotify (or something similar) and set it to the fuzzing output directory to track file creation dates. If time_dict is not specified (or None), the filesystem modification time will be used instead (note that it's difficult to get file *creation* dates on common Linux filesystems, and as such, file *modification* dates are used instead, which will give you an inaccurate plot, as AFL and others modify the seeds after creation, for trimming etc.)

* `time_dict_lock`: if you have trouble with race conditions because you're writing to `time_dict` while also calling `get_coverage`, you can set a lock here to prevent two threads from reading  `time_dict`

* `limit`: only get coverage for these files, ignore the rest (files should be absolute paths). Useful if `corpus` is a directory path but you want to whitelist some specific files.

* `relative_time`: for the plot return value, set key values to relative timings (i.e. start with 0 instead of the actual timestamp of the first file)

* `ignore_missing_files`: do not throw exception when file in corpus is missing

* `use_afl_file_filter`: remove non-corpus files introduced by AFL (e.g. if `corpus` is `/afl_output/` instead of `/afl_output/queue/`, it ignores the bitmap, the stats file etc.)

* `minimum_time`: some files have old modification dates (prior to starting the fuzzing process) if they were copied etc. which messes up your coverage-over-time plot when you use `relative_time`. In these cases, use the supplied `minimum_time` instead.

It returns `(plot, bitmap, final_coverage)` where `plot` is a dictionary in the format `{time: coverage_until_now}`, bitmap is of type `AFLBitmap` and `final_coverage` is the overall number of visited branches.

## Even faster

QuickCov uses the AFL instrumented binary and extracts the bitmap to count the visited branches, but the way that the AFL instrumentation is implemented, there is a high likelihood of collisions, i.e., some new branches will not be seen as new and thus they'll not be counted. Although we've increased the bitmap size tremendously to lower the chances of collisions (from 2^16 to 2^20), the output should still be considered only a good estimate instead of an accurate number. As such, this works better on smaller programs than on larger ones (in terms of basic blocks / edges). There is a collision-free implementation of [AFL++](https://github.com/AFLplusplus/AFLplusplus), and there is also [libAFL](https://github.com/AFLplusplus/LibAFL) which is AFL++ built as a library, so QuickCov might be updated in the future with these changes in mind.

If you want to increase the speed and lose even more accuracy, edit `config.h` and change this line from

```c
#define MAP_SIZE_POW2       20
```

to

```c
#define MAP_SIZE_POW2       16
```

and then build it all again. You can use any value betweet 16 to 20 to trade in speed for accuracy and vice-versa.

## QEMU

If you don't want to instrument your binary first, there is also built-in QEMU support. You first have to build the qemu stuff as described above, and then you're ready to go (QuickCov detects if the binary was instrumented or not and decides which mode to use, so you don't have to worry about that part).

There is also the possibility to use the QEMU mode to get accurate coverage information (i.e. basic block coverage). See above for how much it impacts the performance. If you don't mind, you can set the `mode` parameter of `QuickCov` to `ExecuterMode.AFL_QEMU_BB`, e.g.:

```python
(_, BBs, _) = quickcov.QuickCov("./bin", "@@", mode=ExecuterMode.AFL_QEMU_BB)
```

The `BBs` return value will then be a list of basic block addresses extracted from QEMU.

## PTrace

There is also support for ptrace to get code coverage, but it's super slow, as you can see above, which defeats the whole purpose of this project. It also requires a file with basic-block information which you can extract via IDA. Not recommended.
