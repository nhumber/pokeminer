# -*- coding: utf-8 -*-
from datetime import datetime
import argparse
import logging
import os
import random
import sys
import threading
import time

# from s2sphere import *
# from transform import *
import requests

import api
import config
import db
import utils


pokemons = {}
workers = {}
local_data = threading.local()
api.local_data = local_data


def configure_logger(filename='worker.log'):
    logging.basicConfig(
        filename=filename,
        format=(
            '[%(asctime)s][%(threadName)10s][%(levelname)8s][L%(lineno)4d] '
            '%(message)s'
        ),
        style='{',
        level=logging.INFO,
    )

logger = logging.getLogger()


class Slave(threading.Thread):
    def __init__(
        self,
        group=None,
        target=None,
        name=None,
        worker_no=None,
        points=None,
    ):
        super(Slave, self).__init__(group, target, name)
        self.worker_no = worker_no
        local_data.worker_no = worker_no
        self.points = points
        self.count_points = len(self.points)
        self.step = 0
        self.cycle = 0
        self.seen = 0
        self.error_code = None

    def run(self):
        self.cycle = 1
        self.error_code = None

        # Login sequentially for PTC
        service = config.ACCOUNTS[self.worker_no][2]
        api_session = local_data.api_session = requests.session()
        api_session.headers.update({'User-Agent': 'Niantic App'})
        api_session.verify = False
        position = api.Position(self.points[0][0], self.points[0][1], 100)
        try:
            api_endpoint, access_token, profile_response = api.login(
                username=config.ACCOUNTS[self.worker_no][0],
                password=config.ACCOUNTS[self.worker_no][1],
                service=service,
                position=position,
            )
        except api.CannotGetProfile:
            # OMG! Sleep for a bit and restart the thread
            self.error_code = 'LOGIN FAIL'
            time.sleep(random.randint(5, 10))
            start_worker(self.worker_no, self.points)
            return
        while self.cycle <= 3:
            self.main(service, api_endpoint, access_token, profile_response)
            self.cycle += 1
            if self.cycle <= 3:
                self.error_code = 'SLEEP'
                time.sleep(random.randint(30, 60))
                self.error_code = None
        self.error_code = 'RESTART'
        time.sleep(random.randint(30, 60))
        start_worker(self.worker_no, self.points)

    def main(self, service, api_endpoint, access_token, profile_response):
        session = db.Session()
        self.seen = 0
        for i, point in enumerate(self.points):
            logger.info('Visiting point %d (%s %s)', i, point[0], point[1])
            pokemons = api.process_step(
                service,
                api_endpoint,
                access_token,
                profile_response,
                lat=point[0],
                lon=point[1],
            )
            for pokemon in pokemons:
                db.add_sighting(session, spawn_id, pokemon)
                self.seen += 1
            logger.info('Point processed, %d Pokemons seen!', len(pokemons))
            session.commit()
            # Clear error code and let know that there are Pokemon
            if self.error_code and self.seen:
                self.error_code = None
            self.step += 1
        session.close()
        if self.seen == 0:
            self.error_code = 'NO POKEMON'

    @property
    def status(self):
        if self.error_code:
            msg = self.error_code
        else:
            msg = 'C{cycle},P{seen},{progress:.0f}%'.format(
                cycle=self.cycle,
                seen=self.seen,
                progress=(self.step / float(self.count_points) * 100)
            )
        return '[W{worker_no}: {msg}]'.format(
            worker_no=self.worker_no,
            msg=msg
        )


def get_status_message(workers, count, start_time, points_stats):
    messages = [workers[i].status.ljust(20) for i in range(count)]
    running_for = datetime.now() - start_time
    output = [
        'PokeMiner\trunning for {}'.format(running_for),
        '{len} workers, each visiting ~{avg} points per cycle '
        '(min: {min}, max: {max})'.format(
            len=len(workers),
            avg=points_stats['avg'],
            min=points_stats['min'],
            max=points_stats['max'],
        ),
        '',
    ]
    previous = 0
    for i in range(4, count + 4, 4):
        output.append('\t'.join(messages[previous:i]))
        previous = i
    return '\n'.join(output)


def start_worker(worker_no, points):
    # Ok I NEED to global this here
    global workers
    logger.info('Worker (re)starting up!')
    worker = Slave(
        name='worker-%d' % worker_no,
        worker_no=worker_no,
        points=points
    )
    worker.daemon = True
    worker.start()
    workers[worker_no] = worker


def spawn_workers(workers, status_bar=True):
    points = utils.get_points_per_worker()
    start_date = datetime.now()
    count = config.GRID[0] * config.GRID[1]
    for worker_no in range(count):
        start_worker(worker_no, points[worker_no])
    lenghts = [len(p) for p in points]
    points_stats = {
        'max': max(lenghts),
        'min': min(lenghts),
        'avg': sum(lenghts) / float(len(lenghts)),
    }
    last_cleaned_cache = time.time()
    while True:
        now = time.time()
        if now - last_cleaned_cache > (15 * 60):
            db.CACHE.clean_expired()
        if status_bar:
            if sys.platform == 'win32':
                _ = os.system('cls')
            else:
                _ = os.system('clear')
            print get_status_message(workers, count, start_date, points_stats)
        time.sleep(0.5)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--no-status-bar',
        dest='status_bar',
        help='Log to console instead of displaying status bar',
        action='store_false',
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default=logging.INFO
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    if args.status_bar:
        configure_logger(filename='worker.log')
        logger.info('-' * 30)
        logger.info('Starting up!')
    else:
        configure_logger(filename=None)
    logger.setLevel(args.log_level)
    spawn_workers(workers, status_bar=args.status_bar)
