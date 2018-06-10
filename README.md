# Megabuy API

## Installation

Install all dependencies with `pip install -r requirements.txt`.

Install `sqlite3` `sudo apt-get install sqlite3` on your system.

Now run `python` from command line in the same directory where you cloned this repo.

```python
from server import db
db.create_all()
```
Next we add some exports to your environment.

```sh
export SECRET='your secret goes here'
export DATABASE_URI='your absolute database path'
export MAIL_SERVER='your smtp server address goes here'
export MAIL_PASSWORD='your mail password goes here'
export MAIL_USERNAME='your mail address goes here'
```

Then we make sure the port 5000 is not used

```sh
sudo netstat -tulpen
```

Now you may want to start the server `./server.py`. You shoud see an output like this

```sh
 * Serving Flask app "server" (lazy loading)
 * Debug mode: on
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
```
