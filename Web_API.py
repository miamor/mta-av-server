import os
from flask import Flask,jsonify, request, redirect, url_for, send_from_directory
import json
import logging

class Task(object):
    def __init__(self, filename, result, point):
        self.filename = filename
        self.result = result
        self.point = point

    def obj_dict(self):
        return {'filename': self.filename, 'result': self.result, 'point': self.point}

#UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['exe', 'cpl', 'reg', 'ini', 'bat', 'com', 'dll', 'pif', 'lnk', 'scr', 'vbs', 'ocx', 'drv', 'sys'])
#logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)
#app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    prop = filename.split('.')[-1]
    return prop in ALLOWED_EXTENSIONS

@app.route('/upload-file', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file and allowed_file(file.filename):
        # dua file vao cuckoo xu li https://cuckoo.readthedocs.io/en/latest/usage/api/
        print('----- found file: ', file.filename)
        #file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))

        # tra ve kq nhu vd duoi
        task = Task('1','2','3') 	
        return jsonify({'results' : task.obj_dict(), 'msg':'ok'})
    return jsonify({'msg': 'error'})

@app.route('/upload-multifile', methods=['POST'])
def upload_files():
    #logging.info(request.files)
    if 'files[]' not in request.files:
        return jsonify({'msg': 'error'})
    files = request.files.getlist('files[]')
    for file in files:
        if file and allowed_file(file.filename):
            # Dua file vao cuckoo de xu li  https://cuckoo.readthedocs.io/en/latest/usage/api/
            print('----- found file: ', file.filename)
            #file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))

    # tra ve kq nhu vd duoi  
    task = []
    task.append(Task(1,2,3).obj_dict())
    task.append(Task(2,3,4).obj_dict())
    #results = [obj.obj_dict() for obj in task]
    return jsonify({'results' : task, 'msg' : 'ok'})

if __name__ == '__main__':
	app.run(host="127.0.0.1", port = 8123, debug=True)