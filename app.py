# app.py
from flask import Flask, render_template_string
from detector import alerts

app = Flask(__name__)

PAGE = """
<!doctype html>
<html>
<head><title>Network IDS Alerts</title></head>
<body>
  <h2>Network Intrusion Detection - Alert Monitor</h2>
  <p>Educational prototype. Alerts require human review.</p>
  <table border="1" cellpadding="6">
    <tr><th>Time</th><th>Source</th><th>Destination</th>
        <th>Protocol</th><th>Reason</th></tr>
    {% for a in events %}
    <tr>
      <td>{{ a.time }}</td><td>{{ a.source }}</td>
      <td>{{ a.destination }}</td><td>{{ a.protocol }}</td>
      <td>{{ a.reason }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""


@app.route("/")
def dashboard():
    return render_template_string(PAGE, events=list(reversed(alerts[-100:])))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)