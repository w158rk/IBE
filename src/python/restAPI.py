from fastapi import FastAPI 

app = FastAPI() 

@app.get("/")
def root():
    return "Rest API for a Node"

@app.get("/sk/request")
def request_for_sk():
    return "request for sk"