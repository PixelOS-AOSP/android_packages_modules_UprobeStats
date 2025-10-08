import argparse
from importlib import resources
import os
import subprocess
import sys
import tempfile
import time
import config_pb2
import google.protobuf.text_format as text_format

kwargs = {
    "text": True,
    "shell": True,
    "capture_output": True,
    "check": True,
}


def adb_root():
  subprocess.run("adb root", **kwargs)


def create_and_push_config_proto(name="test_slog"):
  with resources.open_text("test", f"{name}.textproto") as textproto:
    message = text_format.Parse(
        textproto.read(), config_pb2.UprobestatsConfig()
    )
    textproto.close()

    with tempfile.NamedTemporaryFile() as temp:
      temp.write(message.SerializeToString())
      temp.flush()
      print(f"creating {name}")
      config_cmd = (
          f"adb push {temp.name} /data/misc/uprobestats-configs/config"
      )
      subprocess.run(config_cmd, **kwargs)


def clear_logcat():
  print("clearing logcat")
  subprocess.run("adb logcat -c", **kwargs)


def start_uprobestats(run_as_shell=False):
  if (run_as_shell):
    print("starting uprobestats as Shell")
    subprocess.run(
      f"adb shell /apex/com.android.uprobestats/bin/uprobestats", **kwargs)
  else:
    print("starting uprobestats")
    subprocess.run(
        f"adb shell setprop ctl.start uprobestats", **kwargs)

def get_ring_buffer_values():
  time.sleep(10)
  lines = subprocess.run(
      'adb logcat -d | grep "ringbuf result callback. value:"', **kwargs
  ).stdout.splitlines()
  for line in lines:
    print(line)


def get_ring_buffer_size():
  # print('generating log messages and fetching ring buffer size')
  # subprocess.run('adb shell killall com.google.android.apps.photos', shell=True)
  # time.sleep(2)
  # subprocess.run(
  #    'adb shell monkey -p com.google.android.apps.photos -c'
  #    ' android.intent.category.LAUNCHER 1',
  #    **kwargs,
  # )
  ring_buffer_size = (
      subprocess.run(
          'adb logcat -d | grep "uprobestats: ring buffer size"', **kwargs
      )
      .stdout.splitlines()[0]
      .split(":")[4]
      .split(" ")[1]
      .strip()
  )

  print(f"ring buffer size: {ring_buffer_size}")
  return int(ring_buffer_size, 0)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      "Drops a uprobestats config over adb and checks start it. Optionally acts"
      " as a test by checking logcat output"
  )
  parser.add_argument(
      "-n",
      "--name",
      type=str,
      default="test_slog",
      help="Name of the config file e.g. test_slog",
  )
  parser.add_argument(
      "-t",
      "--test",
      default=False,
      action="store_true",
      help=(
          "Run a test, meaning start uprobestats and then look for particular"
          " logcat output to exit successfully"
      ),
  )
  parser.add_argument(
    "-s",
    action="store_true",  # Store True if the flag is present
    help="Run uprobestats as Shell",
)
  args = parser.parse_args()

  adb_root()
  create_and_push_config_proto(args.name)

  if not args.test:
    start_uprobestats(args.s)
    sys.exit(0)

  clear_logcat()
  start_uprobestats(args.s)
  time.sleep(60)
  ring_buf = get_ring_buffer_size()
  get_ring_buffer_values()
  if ring_buf > 0:
    sys.exit(0)
  else:
    raise SystemExit("Did not find a ring buffer greater than zero")
