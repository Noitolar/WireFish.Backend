import flask
import flask_cors
import json
import api

app = flask.Flask(__name__)
flask_cors.CORS(app, resource={r'/*': {'origins': '*'}})
FLASK_DEBUG = 1

sniffer = api.WireFishSniffer()


@app.route("/")
def index():
    return "<h1>Hello!<h1/>"


@app.route("/api/get_interfaces", methods=["get"])
def get_interfaces():
    interfaces = [interface_info[1] for interface_info in sniffer.get_network_interfaces()]
    return flask.jsonify({"result": f"{len(interfaces)} interfaces detected.", "data": interfaces})


@app.route("/api/set_interface", methods=["get"])
def set_interface():
    if sniffer.status == "idle":
        target_interface = flask.request.args.get("new_interface")
        if target_interface in [interface_info[1] for interface_info in sniffer.get_network_interfaces()]:
            sniffer.reset()
            sniffer.target_interface = target_interface
            return flask.jsonify({"result": f"new interface {target_interface} set."})
        else:
            return flask.jsonify({"result": f"interface {target_interface} is invalid."})
    else:
        return flask.jsonify({"result": "sniffer is buzy."})


@app.route("/api/set_filter", methods=["get"])
def set_filter():
    if sniffer.status == "idle":
        new_filter = flask.request.args.get("new_filter")
        sniffer.packet_filter = new_filter
        return flask.jsonify({"result": f"new filter {new_filter} set."})
    else:
        return flask.jsonify({"result": "sniffer is buzy."})


@app.route("/api/test_sniffer", methods=["get"])
def test_sniffer():
    if sniffer.status == "idle":
        sniffer.sniff_offline()
        return flask.jsonify({"result": f"sniff completed. {len(sniffer.infos)} packets captured."})
    else:
        return flask.jsonify({"result": "sniffer is buzy."})


@app.route("/api/start_sniffer", methods=["get"])
def start_sniffer():
    if sniffer.status == "idle":
        count = int(flask.request.args.get("count"))
        timeout = int(flask.request.args.get("timeout"))
        sniffer.sniff_realtime(count, timeout)
        return flask.jsonify({"result": f"sniff completed. {len(sniffer.infos)} packets captured."})
    else:
        return flask.jsonify({"result": "sniffer is buzy."})


@app.route("/api/update", methods=["get"])
def update():
    num_current = int(flask.request.args.get("num_current"))
    if sniffer.status == "idle":
        if num_current == len(sniffer.infos):
            return flask.jsonify({"result": "sniffer has stopped.", "data": []})
        else:
            # return flask.jsonify({"result": "this is the last update.", "data": sniffer.get_update(num_current)})
            return flask.Response(json.dumps({"result": "this is the last update.", "data": sniffer.get_update(num_current)}), mimetype="application/json")
    else:
        # return flask.jsonify({"result": "updated.", "data": sniffer.get_update(num_current)})
        return flask.Response(json.dumps({"result": "updated.", "data": sniffer.get_update(num_current)}), mimetype="application/json")


@app.route("/api/sessions", methods=["get"])
def sessions():
    if sniffer.packets is None:
        return flask.jsonify({"result": "sniffer hasn't capture anything yet.", "data": []})
    elif sniffer.status == "buzy":
        return flask.jsonify({"result": "sniffer is buzy.", "data": []})
    else:
        return flask.jsonify({"result": "sessions extracted.", "data": sniffer.extract_sessions()})


if __name__ == "__main__":
    app.run(host="localhost", port=5000)
    print("app running at http://localhost:5000")
