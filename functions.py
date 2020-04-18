import requests
import sys
sys.path.insert(0, '/home/mtaav/CODE/HAN_sec_new')
import han_sec_api as han

cuckoo_API = 'http://localhost:1337'
SECRET_KEY = "Bearer RALTrRjHNT21MZdDCksugg"
hash_type = 'sha256'
# set CONFIG_PATH in han_sec_api

def start_analysis(filepath):
    REST_URL = cuckoo_API+"/tasks/create/file"
    HEADERS = {"Authorization": SECRET_KEY}

    with open(filepath, "rb") as sample:
        files = {"file": ("temp_file_name", sample)}
        r = requests.post(REST_URL, headers=HEADERS, files=files)

    # Add your code to error checking for r.status_code.
    task_id = r.json()["task_id"]

    # Add your code for error checking if task_id is None.

    return task_id


def get_task_status(task_id):
    REST_URL = cuckoo_API+"/tasks/view/{}".format(task_id)
    HEADERS = {"Authorization": SECRET_KEY}

    r = requests.get(REST_URL, headers=HEADERS)

    task = r.json()["task"]
    print('task', task)

    if 'errors' in task:
        return task['status'], task['errors'], task['sample'][hash_type]
    
    return None, None, None



def check_malware(task_id, res):
    REST_URL = cuckoo_API+"/tasks/report/{}".format(task_id)
    HEADERS = {"Authorization": SECRET_KEY}

    r = requests.get(REST_URL, headers=HEADERS)

    task = r.json()
    task_info = task["info"]

    # print('task', task)
    # print("task_info['score']=", task_info['score'])
    # return task_info['score'], task['virustotal']['scans']
    virustotal_res = {
        'is_malware': 0,
        'score': 0,
        'msg': ''
    }
    virustotal_detected = 0
    virustotal_tot_engine = 0
    if 'scans' in task['virustotal']:
        for engine_name in task['virustotal']['scans']:
            engine_res = task['virustotal']['scans'][engine_name]
            print('engine_res', engine_res)
            virustotal_tot_engine += 1
            if engine_res['detected'] is True:
                virustotal_detected += 1
    if virustotal_tot_engine > 0:
        virustotal_res['score'] = virustotal_detected / virustotal_tot_engine
        virustotal_res['msg'] = '{}/{} engines detected as malware'.format(virustotal_detected, virustotal_tot_engine)
        if virustotal_res['score'] > 0.4:
            virustotal_res['is_malware'] = 1
    else:
        virustotal_res['msg'] = 'No virustotal scans found'

    cuckoo_res = {
        'is_malware': task_info['score'] > 0,
        'score': task_info['score'],
        'msg': ''
    }

    return {
        'cuckoo': cuckoo_res,
        'virustotal': virustotal_res
    }



def check_malware_HAN(task_ids):
    num_task = len(task_ids)
    # data, args = prepare_files([9])
    data, args = han.prepare_files(task_ids, cuda=False)
    print('*** data', data)
    if data is None:
        print('Graph can\'t be created!')
        return [0]*num_task, [0]*num_task, ['Graph can\'t be created!']*num_task
    else:
        print('task_ids', task_ids)
        print('len data', len(data))
        labels, scores = han.predict_files(data, args, cuda=False)
        labels = labels.cpu().numpy().tolist()
        scores = scores.cpu().numpy().tolist()
        print('labels, scores', labels, scores)
        return labels, scores, None
    
    return None, None, None