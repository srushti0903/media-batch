import glob, subprocess, sys
sys.exit(subprocess.call([sys.executable, "-W", "ignore", glob.glob("*/engine/cloudrun.py")[0], *sys.argv[1:]]))
