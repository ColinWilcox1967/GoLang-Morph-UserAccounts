@echo off 
curl --header "Content-Type: application/json" --data  "{\"username\":\"user9\",\"password\":\"pass9\"}" http://localhost:8080/login
