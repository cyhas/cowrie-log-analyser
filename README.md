# cowrie-log-analyser
This simple python program analyses the logs produced by a Cowrie honeypot docker image.

## Prerequisites
- Python 3.6+ (uses only standard library modules)

## Setup Cowrie Honeypot
First, you'll need to set up a Cowrie honeypot using Docker. Follow the instructions from the [official Cowrie repository](https://github.com/cowrie/cowrie):

```bash
# Quick start - run Cowrie in Docker
docker run -p 2222:2222 cowrie/cowrie:latest

# Test the connection
ssh -p 2222 root@localhost
```

### Usage
1. Clone the repository & cd into it

2. Collect logs from your running Cowrie container

```bash
sudo docker logs -f <container_name_or_id> > logs/logs.txt
```

**Note:** Press `CTRL+C` to stop log collection after a few seconds. The log file can get quite large, mine was ~240MB after a month of running on a VPS.

3. Run main.py after the logs are inside the log directory or specify the location of the logs.

```bash
usage: main.py [-h] [-o OUTPUT] [-v] [log_file]

example:
python3 main.py
python3 main.py /home/user/logs.txt
python3 main.py /home/user/logs.txt -o report.txt
```

## Directory Structure
```
cowrie-logs-analyser/
├── logs/ # Place your Cowrie log files here
├── output/ # Generated analysis reports go here
├── main.py # The analyzer script
└── README.md # This file
```

The analyzer will automatically look for `logs.txt` in the `logs/` directory if you don't specify a file path. Reports are saved to the `output/` directory with timestamps.

## Sample Data
This repository includes sample Cowrie logs and a sample analysis report so you can test the analyzer without setting up your own honeypot. Check out the `logs/` and `output/` directories to see examples of the expected input and output formats.