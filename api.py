# -*- coding: utf-8 -*-
from collections import namedtuple
from datetime import datetime
import json
import logging
import random
import re
import struct
import time

from google.protobuf.internal import encoder
from google.protobuf.message import DecodeError
from gpsoauth import perform_master_login, perform_oauth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.adapters import ConnectionError
from requests.models import InvalidURL
from s2sphere import Cell, CellId, LatLng
# from transform import *
import requests

import config
import pokemon_pb2


local_data = None  # this should be set from outside


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

API_URL = 'https://pgorelease.nianticlabs.com/plfe/rpc'
LOGIN_URL = (
    'https://sso.pokemon.com/sso/login?service='
    'https://sso.pokemon.com/sso/oauth2.0/callbackAuthorize'
)
LOGIN_OAUTH = 'https://sso.pokemon.com/sso/oauth2.0/accessToken'
APP = 'com.nianticlabs.pokemongo'

with open('credentials.json') as file:
    credentials = json.load(file)

PTC_CLIENT_SECRET = credentials.get('ptc_client_secret', None)
ANDROID_ID = credentials.get('android_id', None)
SERVICE = credentials.get('service', None)
CLIENT_SIG = credentials.get('client_sig', None)
GOOGLEMAPS_KEY = credentials.get('gmaps_key', None)

# TODO: these should go away
COORDS_LATITUDE = 0
COORDS_LONGITUDE = 0
COORDS_ALTITUDE = 0
FLOAT_LAT = 0
FLOAT_LONG = 0
NEXT_LAT = 0
NEXT_LONG = 0
# /TODO


logger = logging.getLogger()


class CannotGetProfile(Exception):
    """As name says, raised when login service is unreachable

    This should make thread sleep for a moment and restart itself.
    """


Position = namedtuple('Position', 'lat lon alt')


def debug(message):
    logger.info(message)


def encode(cellid):
    output = []
    encoder._VarintEncoder()(output.append, cellid)
    return ''.join(output)


def get_neighbours():
    origin = CellId.from_lat_lng(
        LatLng.from_degrees(FLOAT_LAT, FLOAT_LONG)
    ).parent(15)
    walk = [origin.id()]

    # 10 before and 10 after

    next = origin.next()
    prev = origin.prev()
    for i in range(10):
        walk.append(prev.id())
        walk.append(next.id())
        next = next.next()
        prev = prev.prev()
    return walk


def f2i(float):
    return struct.unpack('<Q', struct.pack('<d', float))[0]


def f2h(float):
    return hex(struct.unpack('<Q', struct.pack('<d', float))[0])


def h2f(hex):
    return struct.unpack('<d', struct.pack('<Q', int(hex, 16)))[0]


def set_location_coords(lat, long, alt):
    global COORDS_LATITUDE, COORDS_LONGITUDE, COORDS_ALTITUDE
    global FLOAT_LAT, FLOAT_LONG
    FLOAT_LAT = lat
    FLOAT_LONG = long
    COORDS_LATITUDE = f2i(lat)  # 0x4042bd7c00000000 # f2i(lat)
    COORDS_LONGITUDE = f2i(long)  # 0xc05e8aae40000000 #f2i(long)
    COORDS_ALTITUDE = f2i(alt)


def get_location_coords():
    return (COORDS_LATITUDE, COORDS_LONGITUDE, COORDS_ALTITUDE)


def retrying_api_req(*args, **kwargs):
    while True:
        try:
            response = api_req(*args, **kwargs)
            if response:
                return response
            logger.debug('retrying_api_req: api_req returned None, retrying')
        except (InvalidURL, ConnectionError, DecodeError) as e:
            logger.debug(
                'retrying_api_req: request error (%s), retrying',
                str(e)
            )
        time.sleep(1)


def api_req(service, api_endpoint, access_token, position, request, useauth):
    p_req = pokemon_pb2.RequestEnvelop()
    p_req.rpc_id = 1469378659230941192

    p_req.unknown1 = 2

    p_req.latitude = f2i(position.lat)
    p_req.longitude = f2i(position.lon)
    p_req.altitude = f2i(position.alt)

    p_req.unknown12 = 989

    if useauth:
        p_req.unknown11.unknown71 = useauth.unknown71
        p_req.unknown11.unknown72 = useauth.unknown72
        p_req.unknown11.unknown73 = useauth.unknown73
    else:
        p_req.auth.provider = service
        p_req.auth.token.contents = access_token
        p_req.auth.token.unknown13 = 14

    p_req.MergeFrom(request)

    protobuf = p_req.SerializeToString()

    session = local_data.api_session
    r = session.post(api_endpoint, data=protobuf, verify=False)

    p_ret = pokemon_pb2.ResponseEnvelop()
    p_ret.ParseFromString(r.content)

    if False:  # VERBOSE_DEBUG
        print 'REQUEST:'
        print p_req
        print 'Response:'
        print p_ret
        print '\n\n'
    time.sleep(config.SLEEP_AFTER_REQUEST)
    return p_ret


def get_api_endpoint(service, access_token, position, api_endpoint=API_URL):
    profile_response = None
    while not profile_response:
        profile_response = retrying_get_profile(
            service=service,
            api_endpoint=api_endpoint,
            access_token=access_token,
            useauth=None,
            position=position,
        )
        if not hasattr(profile_response, 'api_url'):
            logger.debug('get_profile returned no api_url, retrying')
            profile_response = None
            continue
        if not len(profile_response.api_url):
            logger.debug('get_profile returned no-len api_url, retrying')
            profile_response = None
    return 'https://%s/rpc' % profile_response.api_url


def retrying_get_profile(*args, **kwargs):
    profile_response = None
    times_tried = 0
    while not profile_response:
        if times_tried > 5:
            raise CannotGetProfile
        profile_response = get_profile(*args, **kwargs)
        if not getattr(profile_response, 'payload'):
            logger.debug('get_profile returned no or no-len payload, retrying')
            profile_response = None
            times_tried += 1
            continue
    return profile_response


def get_profile(service, api_endpoint, access_token, useauth, position, *args):
    request = pokemon_pb2.RequestEnvelop()
    request_types = [1, 126, 4, 129, 5]  # TODO: what do those mean?
    for request_type, arg in zip(args, request_types):
        req = request.requests.add()
        req.type = 2
        req.MergeFrom(arg)
    return retrying_api_req(
        service=service,
        api_endpoint=api_endpoint,
        access_token=access_token,
        position=position,
        request=request,
        useauth=useauth
    )


def login_google(username, password):
    logger.info('Google login for: %s', username)
    r1 = perform_master_login(username, password, ANDROID_ID)
    r2 = perform_oauth(
        username,
        r1.get('Token', ''),
        ANDROID_ID,
        SERVICE,
        APP,
        CLIENT_SIG,
    )
    return r2.get('Auth')


def login_ptc(username, password):
    logger.info('PTC login for: %s', username)
    head = {'User-Agent': 'Niantic App'}
    session = local_data.api_session
    r = session.get(LOGIN_URL, headers=head)
    try:
        jdata = json.loads(r.content)
    except ValueError:
        logger.warning('login_ptc: could not decode JSON from %s', r.content)
        return None
    # Maximum password length is 15
    # (sign in page enforces this limit, API does not)
    if len(password) > 15:
        logger.debug('Trimming password to 15 characters')
        password = password[:15]

    data = {
        'lt': jdata['lt'],
        'execution': jdata['execution'],
        '_eventId': 'submit',
        'username': username,
        'password': password,
    }
    r1 = session.post(LOGIN_URL, data=data, headers=head)

    ticket = None
    try:
        ticket = re.sub('.*ticket=', '', r1.history[0].headers['Location'])
    except Exception:
        logger.debug('Error: %s', r1.json()['errors'][0])
        return None

    data1 = {
        'client_id': 'mobile-app_pokemon-go',
        'redirect_uri': 'https://www.nianticlabs.com/pokemongo/error',
        'client_secret': PTC_CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'code': ticket,
    }
    r2 = session.post(LOGIN_OAUTH, data=data1)
    access_token = re.sub('&expires.*', '', r2.content)
    access_token = re.sub('.*access_token=', '', access_token)
    return access_token


def get_heartbeat(service, api_endpoint, access_token, response, position):
    m4 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleInt()
    m.f1 = int(time.time() * 1000)
    m4.message = m.SerializeToString()
    m5 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleString()
    m.bytes = '05daf51635c82611d1aac95c0b051d3ec088a930'
    m5.message = m.SerializeToString()
    walk = sorted(get_neighbours())
    m1 = pokemon_pb2.RequestEnvelop.Requests()
    m1.type = 106
    m = pokemon_pb2.RequestEnvelop.MessageQuad()
    m.f1 = ''.join(map(encode, walk))
    m.f2 = (
        '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000'
        '\000\000\000\000'
    )
    m.lat = f2i(position.lat)
    m.long = f2i(position.lon)
    m1.message = m.SerializeToString()
    response = get_profile(
        service,
        access_token,
        api_endpoint,
        response.unknown7,
        m1,
        pokemon_pb2.RequestEnvelop.Requests(),
        m4,
        pokemon_pb2.RequestEnvelop.Requests(),
        m5,
    )

    try:
        payload = response.payload[0]
        heartbeat = pokemon_pb2.ResponseEnvelop.HeartbeatPayload()
    except (AttributeError, IndexError):
        return

    heartbeat.ParseFromString(payload)
    return heartbeat


def get_token(service, username, password):
    if service == 'ptc':
        token = None
        while not token:
            token = login_ptc(username, password)
            if not token:
                logger.info('Could not login to PTC - sleeping')
                time.sleep(random.randint(10, 20))
    else:
        token = login_google(username, password)
    return token


def login(username, password, service, position):
    access_token = get_token(service, username, password)
    if access_token is None:
        raise Exception('[-] Wrong username/password')

    logger.debug('RPC Session Token: %s...', access_token[:25])

    api_endpoint = get_api_endpoint(service, access_token, position)
    if api_endpoint is None:
        raise Exception('[-] RPC server offline')

    logger.debug('Received API endpoint: %s', api_endpoint)

    profile_response = retrying_get_profile(
        service=service,
        access_token=access_token,
        api_endpoint=api_endpoint,
        position=position,
        useauth=None,
    )
    if profile_response is None or not profile_response.payload:
        raise Exception('Could not get profile')

    logger.info('Login successful')

    payload = profile_response.payload[0]
    profile = pokemon_pb2.ResponseEnvelop.ProfilePayload()
    profile.ParseFromString(payload)
    logger.debug('Username: %s', profile.profile.username)

    creation_time = datetime.fromtimestamp(
        int(profile.profile.creation_time) / 1000
    )
    logger.debug(
        'You started playing Pokemon Go on: %s',
        creation_time.strftime('%Y-%m-%d %H:%M:%S')
    )

    for curr in profile.profile.currency:
        logger.debug('%s: %s', curr.type, curr.amount)

    return api_endpoint, access_token, profile_response


def process_step(
    service, api_endpoint, access_token, profile_response, lat, lon
):
    logger.debug('Searching for Pokemon at location %s %s', lat, lon)
    parent = CellId.from_lat_lng(
        LatLng.from_degrees(lat, lon)
    ).parent(15)
    heartbeat = get_heartbeat(
        service,
        api_endpoint,
        access_token,
        profile_response,
        Position(lat, lon, None),
    )
    heartbeats = [heartbeat]
    seen = set([])

    for child in parent.children():
        lat_lng = LatLng.from_point(Cell(child).get_center())
        heartbeats.append(get_heartbeat(
            service,
            api_endpoint,
            access_token,
            profile_response,
            Position(lat_lng.lat().degrees, lat_lng.lng().degrees, None),
        ))
    visible = []

    for hh in heartbeats:
        try:
            for cell in hh.cells:
                for wild in cell.WildPokemon:
                    pokemon_hash = '{}:{}'.format(
                        wild.SpawnPointId,
                        wild.pokemon.PokemonId
                    )
                    if pokemon_hash not in seen:
                        visible.append(wild)
                        seen.add(pokemon_hash)
        except AttributeError:
            break

    result = []
    for poke in visible:
        if poke.TimeTillHiddenMs < 10 * 1000:
            continue
        disappear_timestamp = time.time() + poke.TimeTillHiddenMs / 1000
        result.append({
            'lat': poke.Latitude,
            'lng': poke.Longitude,
            'disappear_time': disappear_timestamp,
            'id': poke.pokemon.PokemonId,
        })
    return result
