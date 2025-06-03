## run

nohup python app.py > flask_app.log 2>&1 &


## download_from_url
post http://localhost:8000/download_from_url

{
    "url": "https://s.coze.cn/t/48-sYvSFo5Y/"
}
## feedback
{
    "file_url": "http://localhost:8000/95ce6b33-baea-4419-bafc-75f8ef360341.png",
    "filename": "95ce6b33-baea-4419-bafc-75f8ef360341.png",
    "original_url": "https://s.coze.cn/t/48-sYvSFo5Y/"
}

## upload
post http://localhost:8000/upload

form-data
file=@"filepath"

## feedback
{
    "file_url": "http://localhost:8000/xxxxx.jpg"
}
