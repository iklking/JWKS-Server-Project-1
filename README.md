# Project 1 ReadMe
Kaylyn King CSCE 3550
## Summary
This is a RESTful JWKS server that verifies JSON Web Keys by generating expired and non-expired web keys upon request in Python.

## Installations Used:
pip install Flask, cyptography, PyJWT
pip install coverage

## How To Run server:
python3 Project1.py

## How To Run Test Client:
go run main.go project1

## How to Run Test Suite:
coverage run -m unittest test_Project1.py
coverage report -m
