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
        return flask.jsonify({"result": f"[o] interface <{target_interface}> selected."})
    else:
        return flask.jsonify({"result": f"[x] interface <{target_interface}> is invalid."})


@app.route("/api/start", methods=["get"])
def start():
    if sniffer.status == "idle":
        count = flask.request.args.get("count")
        timeout = flask.request.args.get("timeout")
        sniffer.sniff_realtime(count, timeout)
        return flask.jsonify({"result": "[o] sniffer starts."})
    else:
        return flask.jsonify({"result": "[x] sniffer is buzy."})


@app.route("/api/set_filter", methods=["get"])
def set_filter():
    if sniffer.status == "idle":
        new_filter = flask.request.args.get("new_filter")
        if sniffer.packet_dump is None:
            sniffer.packet_filter = new_filter
            return flask.jsonify({"result": f"[o] new filter <{new_filter}> set.", "data": ""})
        else:
            sniffer.sniff_offline()
            return flask.jsonify({"result": f"[o] refiltered by new filter <{sniffer.packet_filter}>.", "data": sniffer.get_update(0)})
    else:
        return flask.jsonify({"result": "[x] sniffer is buzy.", "data": ""})


@app.route("/api/update", methods=["get"])
def update():
    num_current = flask.request.args.get("num_current")
    if num_current == len(sniffer.packet_info_dump):
        if sniffer.status == "idle":
            return flask.jsonify({"result": "[o] sniffer has stopped.", "data": ""})
        else:
            return flask.jsonify({"result": "[o] this is the last update.", "data": sniffer.get_update(num_current)})
    else:
        return flask.jsonify({"result": "[o] updated.", "data": sniffer.get_update(num_current)})


if __name__ == "__main__":
    app.run(host="localhost", port=8888)
    print("[o] app running at http://localhost:8888")
