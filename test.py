#!/usr/bin/python3

import unittest, os, shutil
import quickcov

QUEUE_PATH = os.path.abspath("test_queue/")
NUM_RUNS = 3

def get_queue_files(folder):
  files = []
  for d in os.listdir(folder):
    p = os.path.abspath(os.path.join(folder, d))
    if os.path.isdir(p):
      files.extend(get_queue_files(p))
    else:
      files.append(p)
  return files

def reset_queue_dir():
  if os.path.isdir(QUEUE_PATH):
    shutil.rmtree(QUEUE_PATH)
  os.mkdir(QUEUE_PATH)
  os.system("tar -xf test_queue.tar -C %s" % QUEUE_PATH)

class TestAFLBitmap(unittest.TestCase):

  def test_basic(self):
    b = quickcov.AFLBitmap()
    self.assertEqual(b.count(), 0)
    c = quickcov.AFLBitmap(bytearray([0x11, 0xff, 0x12, 0xff, 0x55]))
    self.assertEqual(c.count(), 3)
    d = quickcov.AFLBitmap(bytearray([0x11, 0x05, 0x12, 0xff, 0x55]))
    self.assertEqual(d.count(), 4)
    d.update(c)
    self.assertEqual(d.count(), 4)
    d = quickcov.AFLBitmap(bytearray([0x11, 0x05, 0x12, 0xff, 0x55]))
    c.update(d)
    self.assertEqual(c.count(), 4)

    e = quickcov.AFLBitmap()
    e.update(c)
    self.assertEqual(e.count(), 4)
    self.assertEqual(e.bitmap[0], 1)
    self.assertEqual(e.bitmap[3], 0)

    # test delta functionality
    f = quickcov.AFLBitmap(bytearray([0xff, 0x34, 0xff, 0xff, 0x90, 0xab, 0xff]))
    g = quickcov.AFLBitmap(bytearray([0x12, 0x34, 0xff, 0x78, 0x90, 0xab, 0xff]))
    delta = g.delta(f)
    self.assertEqual(delta.count(), 2)
    delta = g.delta(g)
    self.assertEqual(delta.count(), 0)

class TestBBTrace(unittest.TestCase):

  def test_basic(self):
    b = quickcov.AFLBBTrace()
    self.assertEqual(b.count(), 0)
    c = quickcov.AFLBBTrace([0x11, 0x12, 0x55])
    self.assertEqual(c.count(), 3)
    d = quickcov.AFLBBTrace([0x05, 0x11, 0x12, 0x55])
    self.assertEqual(d.count(), 4)
    d.update(c)
    self.assertEqual(d.count(), 4)
    d = quickcov.AFLBBTrace([0x05, 0x11, 0x12, 0x55])
    c.update(d)
    self.assertEqual(c.count(), 4)

    e = quickcov.AFLBBTrace()
    e.update(c)
    self.assertEqual(e.count(), 4)

    # test delta functionality
    f = quickcov.AFLBBTrace([0x34, 0x90, 0xab])
    g = quickcov.AFLBBTrace([0x12, 0x34, 0x78, 0x90, 0xab])
    delta = g.delta(f)
    self.assertEqual(delta.count(), 2)
    self.assertCountEqual(delta.trace, [0x12, 0x78])
    delta = g.delta(g)
    self.assertEqual(delta.count(), 0)

class TestQuickCov(unittest.TestCase):

    def setUp(self):
      self.mode_to_binary = {
        quickcov.ExecuterMode.AFL: "quickcov_instrumented/objdump",
        quickcov.ExecuterMode.AFL_QEMU: "quickcov_uninstrumented/objdump",
        quickcov.ExecuterMode.AFL_QEMU_BB: "quickcov_uninstrumented/objdump",
        quickcov.ExecuterMode.PTRACE: "quickcov_uninstrumented/objdump"
      }
      reset_queue_dir()

    def test_basic(self):
      for mode in self.mode_to_binary:
        binary = self.mode_to_binary[mode]
        with quickcov.QuickCov(binary, "--dwarf-check -C -g -f -dwarf -x @@", mode=mode) as q:
          plots = {}
          bitmaps = {}
          for i in range(NUM_RUNS):
            # sort files by id to get the creation date
            timestamps = {}
            files = sorted(get_queue_files(QUEUE_PATH))
            for x,f in enumerate(sorted(files)):
              timestamps[f] = x
            (plots[i], bitmaps[i], final_coverage) = q.get_coverage(files, plot=True, time_dict=timestamps)
            self.assertTrue(final_coverage > 1)
            self.assertTrue(bitmaps[i].count() > 0)
            self.assertEqual(len(plots[i].keys()), len(files))
            self.assertTrue(plots[i][min(plots[i].keys())] < plots[i][max(plots[i].keys())])
            last = 0
            for t in sorted(plots[i], key=lambda x: x):
              self.assertTrue(last <= plots[i][t])
              last = plots[i][t]
          for i in range(NUM_RUNS):
            for j in range(NUM_RUNS):
              self.assertCountEqual(plots[i].values(), plots[j].values())

    def test_duplicate_files(self):
      for mode in self.mode_to_binary:
        binary = self.mode_to_binary[mode]
        with quickcov.QuickCov(binary, "--dwarf-check -C -g -f -dwarf -x @@", mode=mode) as q:
          # sort files by id to get the creation date
          timestamps = {}
          files = sorted(get_queue_files(QUEUE_PATH))
          for x,f in enumerate(sorted(files)):
            timestamps[f] = x
          (plot, bitmap, final_coverage) = q.get_coverage(files, plot=True, time_dict=timestamps)
          including_duplicate_files = list(files)
          # duplicate files, count coverage again
          for f in files:
            shutil.copyfile(f, os.path.join(os.path.dirname(f), "%s-dup" % os.path.basename(f)))
            including_duplicate_files.append(f)
          (plot_dup, bitmap_dup, final_coverage_dup) = q.get_coverage(including_duplicate_files, plot=True, time_dict=timestamps)
          self.assertEqual(final_coverage, final_coverage_dup)

    def test_one_file(self):
      for mode in self.mode_to_binary:
        binary = self.mode_to_binary[mode]
        with quickcov.QuickCov(binary, "--dwarf-check -C -g -f -dwarf -x @@", mode=mode) as q:
          final_coverages = []
          for i in range(NUM_RUNS):
            # sort files by id to get the creation date
            timestamps = {}
            files = get_queue_files(QUEUE_PATH)
            for x,f in enumerate(sorted(files)):
              timestamps[f] = x
            files = [os.path.join(QUEUE_PATH, "id:000000,orig:a.txt")]
            (plot, bitmap, final_coverage) = q.get_coverage(files, plot=True, time_dict=timestamps)
            final_coverages.append(final_coverage)
          for c1 in final_coverages:
            for c2 in final_coverages:
              self.assertEqual(c1, c2)

    def test_nonexisting_file(self):
      for mode in self.mode_to_binary:
        binary = self.mode_to_binary[mode]
        with quickcov.QuickCov(binary, "--dwarf-check -C -g -f -dwarf -x @@", mode=mode) as q:
          files = get_queue_files(QUEUE_PATH)[:5] + ['this_does_not_exist_145435435']
          (plot, bitmap, final_coverage) = q.get_coverage(files, plot=True)
          self.assertTrue(final_coverage > 1)
          # assert raises error when file does not exist and ignore_missing_files is False
          self.assertRaises(Exception, q.get_coverage, files, plot=True, ignore_missing_files=False)

    def test_minimum_time(self):
      for mode in self.mode_to_binary:
        binary = self.mode_to_binary[mode]
        with quickcov.QuickCov(binary, "--dwarf-check -C -g -f -dwarf -x @@", mode=mode) as q:
          timestamps = {}
          files = get_queue_files(QUEUE_PATH)
          for x,f in enumerate(sorted(files)):
            timestamps[f] = x
          files = get_queue_files(QUEUE_PATH)
          # without minimum time
          (plot, bitmap, final_coverage) = q.get_coverage(files, plot=True, time_dict=timestamps)
          self.assertTrue(min(plot.keys()) == 0)
          # with minimum time
          (plot, bitmap, final_coverage) = q.get_coverage(files, plot=True, time_dict=timestamps, minimum_time=2)
          self.assertTrue(min(plot.keys()) == 2)

    def test_persistent_mode(self):
      with quickcov.QuickCov("quickcov_instrumented/boringssl-2016-02-12", "@@") as q:
        plots = {}
        bitmaps = {}
        for i in range(NUM_RUNS):
          # sort files by id to get the creation date
          timestamps = {}
          files = sorted(get_queue_files(QUEUE_PATH))
          for x,f in enumerate(sorted(files)):
            timestamps[f] = x
          (plots[i], bitmaps[i], final_coverage) = q.get_coverage(files, plot=True, time_dict=timestamps)
          self.assertTrue(final_coverage > 1)
          self.assertEqual(len(plots[i].keys()), len(files))
          last = 0
          for t in sorted(plots[i], key=lambda x: x):
            self.assertTrue(last <= plots[i][t])
            last = plots[i][t]
          # has the first input lower coverage than the last?
          self.assertTrue(plots[i][list(plots[i].keys())[0]] < plots[i][list(plots[i].keys())[-1]])
        for i in range(NUM_RUNS):
          for j in range(NUM_RUNS):
            self.assertCountEqual(plots[i].values(), plots[j].values())

    def test_dump_basic_blocks(self):
      plots = {}
      traces = {}
      for i in range(NUM_RUNS):
        with quickcov.QuickCov("quickcov_uninstrumented/objdump", "--dwarf-check -C -g -f -dwarf -x @@", mode=quickcov.ExecuterMode.AFL_QEMU_BB) as q:
          files = sorted(get_queue_files(QUEUE_PATH))
          (plots[i], traces[i], final_coverage) = q.get_coverage(files, plot=True)
          # is the main function in the trace?
          main_address = 0x400005F6E0
          self.assertTrue(main_address in traces[i].trace)
          # has the first input lower coverage than the last?
          self.assertTrue(plots[i][list(plots[i].keys())[0]] < plots[i][list(plots[i].keys())[-1]])

    def test_dump_basic_blocks_ptrace(self):
      plots = {}
      traces = {}
      for i in range(NUM_RUNS):
        with quickcov.QuickCov("quickcov_uninstrumented/objdump", "--dwarf-check -C -g -f -dwarf -x @@", mode=quickcov.ExecuterMode.PTRACE) as q:
          files = sorted(get_queue_files(QUEUE_PATH))
          (plots[i], traces[i], final_coverage) = q.get_coverage(files, plot=True)
          # is the main function in the trace?
          main_address = 0x5F6E0
          self.assertTrue(main_address in traces[i].trace)
          # has the first input lower coverage than the last?
          self.assertTrue(plots[i][list(plots[i].keys())[0]] < plots[i][list(plots[i].keys())[-1]])

if __name__ == '__main__':
    unittest.main()