import os
import urllib.request
from app import app
from flask import Flask, request, redirect, jsonify
from werkzeug.utils import secure_filename
import functions as fcn
from functions import hash_type
import time

ALLOWED_EXTENSIONS = set(['exe', 'cpl', 'reg', 'ini', 'bat', 'com', 'dll', 'pif', 'lnk', 'scr', 'vbs', 'ocx', 'drv', 'sys', 'ods'])

class Response(object):
    def __init__(self):
        self.resp = {}
    
    def add_response(self, task_id, filename, hash_type, hash_value, is_malware, score, engine, msg=''):
        ''' Add detection result to response '''
        if task_id not in self.resp:
            self.resp[task_id] = {
                'is_malware': is_malware,
                'filename' : filename,
                'hash_type' : hash_type,
                'hash_value' : hash_value,
            }
        else:
            if is_malware == 1:
                self.resp[task_id]['is_malware'] = 1

        self.resp[task_id][engine] = {
            'is_malware' : is_malware,
            'score' : score,
            'msg' : msg
        }

    def get(self):
        return self.resp


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/download-file', methods= ['GET'])
def download_file():
    path = 'Update/'
    lstFile = os.listdir(path)
    print(lstFile)
    date = str(datetime.datetime.now().strftime('%d-%m-%Y'))
    print(date)
    for item in lstFile:
        print(item.split('.')[0])
        if (date == item.split('.')[0]):
            return send_file(item, as_attachment=True)
    abort(404, 'not available')


@app.route("/upload-multiple", methods=["POST"])
def upload_file_multiple():
    # check if the post request has the file part
    if 'files[]' not in request.files:
        return jsonify({'msg': 'error'})
        resp = jsonify({"status": "error", "status_msg": "No file part in the request"})
        resp.status_code = 400
        return resp

    files = request.files.getlist('files[]')
    task_ids = []
    map_task_file = {}
    print('files', files)

    # Create response
    __res__ = Response()
    begin_time = time.time()

    for file in files:
        if file.filename == "":
            continue
        
        done_report = False

        # if file and allowed_file(file.filename):
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            # Run analysis
            task_id = fcn.start_analysis(filepath)
            print("task_id", task_id)
            task_ids.append(task_id)
            map_task_file[task_id] = file

            if task_id is None:
                return jsonify(
                    {"status": "error", "status_msg": "Create task for file {} failed.".format(file.filename)}
                )

            # Now wait until task is complete
            # Keep checking status
            while not done_report:
                task_status, errors, hash_value = fcn.get_task_status(task_id)
                print('errors', errors)
                print('task_status', task_status)
                if task_status == 'reported':
                    done_report = True
                    # if errors is not None:
                    #     return jsonify(
                    #         {"status": "error", "status_msg": "Error analyzing.\n"+'\n'.join(errors)}
                    #     )
                time.sleep(2)


            # Analyzing done. Now get report and check malware
            obj_res = fcn.check_malware(task_id, __res__)
            for engine_name in obj_res:
                engine_res = obj_res[engine_name]
                __res__.add_response(task_id, file.filename, hash_type, hash_value, engine_res['is_malware'], engine_res['score'], engine_name, engine_res['msg'])

        else:
            resp = jsonify(
                {
                    "status": "error",
                    "status_msg": "Allowed file types are {}".format(', '.join(ALLOWED_EXTENSIONS)),
                }
            )
            resp.status_code = 400
            return resp


    # Detect using HAN_sec
    labels, scores, msg = fcn.check_malware_HAN(task_ids)
    if labels is not None:
        if msg is not None:
            for i, task_id in enumerate(task_ids):
                __res__.add_response(task_id, file.filename, hash_type, hash_value, labels[i], scores[i], 'HAN_sec', msg[i])
        else:
            for i, task_id in enumerate(task_ids):
            # for i,file in enumerate(sorted(files)):
                # task_id = task_ids[i]
                file = map_task_file[task_id]
                # if labels[i] == 1 and scores[i] < 0.65:
                #     labels[i] = 0
                #     scores[i] = -scores[i]
                __res__.add_response(task_id, file.filename, hash_type, hash_value, labels[i], scores[i], 'HAN_sec')



    resp = jsonify({
        "status": "success",
        "status_msg": __res__.get(),
    })
    resp.status_code = 200
    print('time', time.time()-begin_time)
    return resp


if __name__ == "__main__":
    app.run(host='192.168.1.137', port=5001)
