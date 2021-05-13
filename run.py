from WebApp import app
import sys


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print('Usage: run.py IP PORT')
        print('IE: python3 run.py 127.0.0.1 7777')
        raise SystemExit

    app.run(host=sys.argv[1], port=int(sys.argv[2]))
