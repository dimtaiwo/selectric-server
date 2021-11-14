def test_cars_get(api):
    resp = api.get('/cars')
    assert resp.status == '200 OK'
    assert b'Tesla' in resp.data
def test_cars_post(api):
    car_data = {
        "brand": 'brand',
        "model": 'model',
        "range_km": 'range_km',
        "efficiency_whkm": 'efficiency_whkm',
        "fast_charge_kmh": 'fast_charge_kmh',
        "rapid_charge": 'rapid_charge',
        "power_train": 'power_train',
        "plug_type": 'plug_type',
        "body_style": 'body_style',
    }
    resp = api.post('/cars',json=car_data)
    assert resp.status =='201 CREATED'
    
def test_register(api):
    user_data = {
        "email": 'bigtest@email.com',
        "password": 'password',
        "username": 'bigtester'
    }
    resp = api.post('/register',json=user_data)
    
    global testToken
    testToken = resp.json['token']
    assert resp.status == '201 CREATED'
   
def test_login(api):
    user_data = {
        "email": 'bigtest@email.com',
        "password": 'password',
        "username": 'bigtester'
    }
    resp = api.post('/login',json=user_data)
    assert resp.status == '200 OK'
def test_get_user(api):
    resp = api.get('/user',headers={"auth-token": testToken})
    assert resp.status == '200 OK'
    assert 'bigtester' in resp.json['username']
def test_patch_user(api):
    resp = api.patch('/user',headers={"auth-token":testToken},json={"updates": [{"name": 'test-update',"value":"test"}]})
    assert resp.status == '201 CREATED'
    assert 'test' in resp.json['test-update']
def test_delete_user(api):
    resp = api.delete('/user',headers={"auth-token":testToken})
    assert resp.status == '200 OK'