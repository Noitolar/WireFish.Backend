import flask
import flask_cors
import api

app = flask.Flask(__name__)
flask_cors.CORS(app, resource={r'/*': {'origins': '*'}})
FLASK_DEBUG = 1

sniffer = api.WireFishSniffer()


@app.route("/")
def index():
    return "<h1>Hello!<h1/>"


@app.route("/api/set_interface", methods=["get"])
def set_interface():
    if sniffer.status == "idle":
        target_interface = flask.request.args.get("new_interface")
        if target_interface in [interface_info[1] for interface_info in sniffer.get_network_interfaces()]:
            sniffer.reset()
            sniffer.target_interface = target_interface
            return flask.jsonify({"result": f"[o] new interface {target_interface} set."})
        else:
            return flask.jsonify({"result": f"[x] interface {target_interface} is invalid."})
    else:
        return flask.jsonify({"result": "[x] sniffer is buzy."})


@app.route("/api/set_filter", methods=["get"])
def set_filter():
    if sniffer.status == "idle":
        new_filter = flask.request.args.get("new_filter")
        if sniffer.packets is None:
            sniffer.packet_filter = new_filter
            return flask.jsonify({"result": f"[o] new filter {new_filter} set."})
        else:
            # sniffer.sniff_offline()
            # return flask.jsonify({"result": f"[o] refiltered by new filter <{sniffer.packet_filter}>.", "data": sniffer.get_update(0)})
            return flask.jsonify({"result": "[x] offline filter is not supportted due to shitty scapy."})
    else:
        return flask.jsonify({"result": "[x] sniffer is buzy."})


@app.route("/api/test_sniffer", methods=["get"])
def test_sniffer():
    if sniffer.status == "idle":
        sniffer.sniff_offline()
        return flask.jsonify({"result": f"[o] sniff completed. {len(sniffer.infos)} packets captured."})
    else:
        return flask.jsonify({"result": "[x] sniffer is buzy."})


@app.route("/api/start_sniffer", methods=["get"])
def start_sniffer():
    if sniffer.status == "idle":
        count = int(flask.request.args.get("count"))
        timeout = int(flask.request.args.get("timeout"))
        sniffer.sniff_realtime(count, timeout)
        return flask.jsonify({"result": f"[o] sniff completed. {len(sniffer.infos)} packets captured."})
    else:
        return flask.jsonify({"result": "[x] sniffer is buzy."})


@app.route("/api/update", methods=["get"])
def update():
    num_current = int(flask.request.args.get("num_current"))
    if sniffer.status == "idle":
        if num_current == len(sniffer.infos):
            return flask.jsonify({"result": "[o] sniffer has stopped.", "data": []})
        else:
            return flask.jsonify({"result": "[o] this is the last update.", "data": sniffer.get_update(num_current)})
    else:
        return flask.jsonify({"result": "[o] updated.", "data": sniffer.get_update(num_current)})


@app.route("/api/sessions", methods=["get"])
def sessions():
    if sniffer.packets is None:
        return flask.jsonify({"result": "[x] sniffer hasn't capture anything yet.", "data": []})
    elif sniffer.status == "buzy":
        return flask.jsonify({"result": "[x] sniffer is buzy.", "data": []})
    else:
        return flask.jsonify({"result": "[o] sessions extracted.", "data": sniffer.extract_sessions()})


if __name__ == "__main__":
    app.run(host="localhost", port=5000)
    print("[o] app running at http://localhost:5000")
