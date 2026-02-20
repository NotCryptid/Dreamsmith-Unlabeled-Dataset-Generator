@echo off
setlocal enabledelayedexpansion

javac -cp toolkit-0.1.jar BatchLevelToJson.java

java -cp "toolkit-0.1.jar;." BatchLevelToJson