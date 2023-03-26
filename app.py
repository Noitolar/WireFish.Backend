import flask
import flask_cors
import api

app = flask.Flask(__name__)
flask_cors.CORS(app, resource={r'/*': {'origins': '*'}})

sniffer = api.WireFishSniffer()


@app.route("/")
def index():
    return "<h1>Hello!<h1/>"


@app.route("/api/select_interface", methods=["get"])
def select_interface():
    target_interface = flask.request.args.get("target_interface")
    if target_interface in [interface_info[1] for interface_info in sniffer.get_network_interfaces()]:
        sniffer.reset()
        sniffer.target_interface = target_interface
        return flask.jsonify({"result": f"[+] interface <{target_interface}> selected."})
    else:
        return flask.jsonify({"result": f"[!] interface <{target_interface}> is invalid."})


@app.route("/api/set_filter", methods=["get"])
def set_filter():
    packet_filter = flask.request.args.get("packet_filter")
    sniffer.packet_filter = packet_filter


app.run(host="localhost", port=8888)
print("[+] app running at http://localhost:8888")
