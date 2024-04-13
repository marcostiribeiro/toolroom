from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.lib.packet import ethernet
from ryu import cfg
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib import ofctl_v1_4
from ryu.lib import ofctl_v1_5
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import WSGIApplication
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
import random, string, base64
from Cryptodome.Cipher import AES
import random, string, base64
from base64 import b64encode
from base64 import b64decode
import ast
import json
import logging
import random
import sys
from builtins import print


class CommandNotFoundError(RyuException):
    message = 'No such command : %(cmd)s'


class PortNotFoundError(RyuException):
    message = 'No such port info: %(port_no)s'


LOG = logging.getLogger('ryu.app.ofctl_rest')

# supported ofctl versions in this restful app
supported_ofctl = {
    ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
    ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
    ofproto_v1_4.OFP_VERSION: ofctl_v1_4,
    ofproto_v1_5.OFP_VERSION: ofctl_v1_5,
}


def stats_method(method):
    def wrapper(self, req, dpid, *args, **kwargs):
        # Get datapath instance from DPSet
        try:
            dp = self.dpset.get(int(str(dpid), 0))
        except ValueError:
            LOG.exception('Invalid dpid: %s', dpid)
            return Response(status=400)
        if dp is None:
            LOG.error('No such Datapath: %s', dpid)
            return Response(status=404)

        # Get lib/ofctl_* module
        try:
            ofctl = supported_ofctl.get(dp.ofproto.OFP_VERSION)
        except KeyError:
            LOG.exception('Unsupported OF version: %s',
                          dp.ofproto.OFP_VERSION)
            return Response(status=501)

        # Invoke StatsController method
        try:
            ret = method(self, req, dp, ofctl, *args, **kwargs)
            return Response(content_type='application/json',
                            body=json.dumps(ret))
        except ValueError:
            LOG.exception('Invalid syntax: %s', req.body)
            return Response(status=400)
        except AttributeError:
            LOG.exception('Unsupported OF request in this version: %s',
                          dp.ofproto.OFP_VERSION)
            return Response(status=501)

    return wrapper


def command_method(method):
    def wrapper(self, req, *args, **kwargs):
        # Parse request json body
        try:
            if req.body:
                # We use ast.literal_eval() to parse request json body
                # instead of json.loads().
                # Because we need to parse binary format body
                # in send_experimenter().
                body = ast.literal_eval(req.body.decode('utf-8'))
            else:
                body = {}
        except SyntaxError:
            LOG.exception('Invalid syntax: %s', req.body)
            return Response(status=400)

        # Get datapath_id from request parameters
        dpid = body.get('dpid', None)
        if not dpid:
            try:
                dpid = kwargs.pop('dpid')
            except KeyError:
                LOG.exception('Cannot get dpid from request parameters')
                return Response(status=400)

        # Get datapath instance from DPSet
        try:
            dp = self.dpset.get(int(str(dpid), 0))
        except ValueError:
            LOG.exception('Invalid dpid: %s', dpid)
            return Response(status=400)
        if dp is None:
            LOG.error('No such Datapath: %s', dpid)
            return Response(status=404)

        # Get lib/ofctl_* module
        try:
            ofctl = supported_ofctl.get(dp.ofproto.OFP_VERSION)
        except KeyError:
            LOG.exception('Unsupported OF version: version=%s',
                          dp.ofproto.OFP_VERSION)
            return Response(status=501)

        # Invoke StatsController method
        try:
            method(self, req, dp, ofctl, body, *args, **kwargs)
            return Response(status=200)
        except ValueError:
            LOG.exception('Invalid syntax: %s', req.body)
            return Response(status=400)
        except AttributeError:
            LOG.exception('Unsupported OF request in this version: %s',
                          dp.ofproto.OFP_VERSION)
            return Response(status=501)
        except CommandNotFoundError as e:
            LOG.exception(e.message)
            return Response(status=404)
        except PortNotFoundError as e:
            LOG.exception(e.message)
            return Response(status=404)

    return wrapper


class StatsController(ControllerBase):
    list_ip_deny = {}

    def __init__(self, req, link, data, **config):
        super(StatsController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    def get_dpids(self, req, **_kwargs):
        dps = list(self.dpset.dps.keys())
        body = json.dumps(dps)
        return Response(content_type='application/json', body=body)

    @stats_method
    def get_desc_stats(self, req, dp, ofctl, **kwargs):
        return ofctl.get_desc_stats(dp, self.waiters)

    @stats_method
    def get_flow_desc(self, req, dp, ofctl, **kwargs):
        flow = req.json if req.body else {}
        return ofctl.get_flow_desc(dp, self.waiters, flow)

    @stats_method
    def get_flow_stats(self, req, dp, ofctl, **kwargs):
        flow = req.json if req.body else {}
        return ofctl.get_flow_stats(dp, self.waiters, flow)

    @stats_method
    def get_aggregate_flow_stats(self, req, dp, ofctl, **kwargs):
        flow = req.json if req.body else {}
        return ofctl.get_aggregate_flow_stats(dp, self.waiters, flow)

    @stats_method
    def get_table_stats(self, req, dp, ofctl, **kwargs):
        return ofctl.get_table_stats(dp, self.waiters)

    @stats_method
    def get_table_features(self, req, dp, ofctl, **kwargs):
        return ofctl.get_table_features(dp, self.waiters)

    @stats_method
    def get_port_stats(self, req, dp, ofctl, port=None, **kwargs):
        if port == "ALL":
            port = None

        return ofctl.get_port_stats(dp, self.waiters, port)

    @stats_method
    def get_queue_stats(self, req, dp, ofctl,
                        port=None, queue_id=None, **kwargs):
        if port == "ALL":
            port = None

        if queue_id == "ALL":
            queue_id = None

        return ofctl.get_queue_stats(dp, self.waiters, port, queue_id)

    @stats_method
    def get_queue_config(self, req, dp, ofctl, port=None, **kwargs):
        if port == "ALL":
            port = None

        return ofctl.get_queue_config(dp, self.waiters, port)

    @stats_method
    def get_queue_desc(self, req, dp, ofctl,
                       port=None, queue=None, **_kwargs):
        if port == "ALL":
            port = None

        if queue == "ALL":
            queue = None

        return ofctl.get_queue_desc(dp, self.waiters, port, queue)

    @stats_method
    def get_meter_features(self, req, dp, ofctl, **kwargs):
        return ofctl.get_meter_features(dp, self.waiters)

    @stats_method
    def get_meter_config(self, req, dp, ofctl, meter_id=None, **kwargs):
        if meter_id == "ALL":
            meter_id = None

        return ofctl.get_meter_config(dp, self.waiters, meter_id)

    @stats_method
    def get_meter_desc(self, req, dp, ofctl, meter_id=None, **kwargs):
        if meter_id == "ALL":
            meter_id = None

        return ofctl.get_meter_desc(dp, self.waiters, meter_id)

    @stats_method
    def get_meter_stats(self, req, dp, ofctl, meter_id=None, **kwargs):
        if meter_id == "ALL":
            meter_id = None

        return ofctl.get_meter_stats(dp, self.waiters, meter_id)

    @stats_method
    def get_group_features(self, req, dp, ofctl, **kwargs):
        return ofctl.get_group_features(dp, self.waiters)

    @stats_method
    def get_group_desc(self, req, dp, ofctl, group_id=None, **kwargs):
        if dp.ofproto.OFP_VERSION < ofproto_v1_5.OFP_VERSION:
            return ofctl.get_group_desc(dp, self.waiters)
        else:
            return ofctl.get_group_desc(dp, self.waiters, group_id)

    @stats_method
    def get_group_stats(self, req, dp, ofctl, group_id=None, **kwargs):
        if group_id == "ALL":
            group_id = None

        return ofctl.get_group_stats(dp, self.waiters, group_id)

    @stats_method
    def get_port_desc(self, req, dp, ofctl, port_no=None, **kwargs):
        if dp.ofproto.OFP_VERSION < ofproto_v1_5.OFP_VERSION:
            return ofctl.get_port_desc(dp, self.waiters)
        else:
            return ofctl.get_port_desc(dp, self.waiters, port_no)

    @stats_method
    def get_role(self, req, dp, ofctl, **kwargs):
        return ofctl.get_role(dp, self.waiters)

    @command_method
    def mod_flow_entry(self, req, dp, ofctl, flow, cmd, **kwargs):
        cmd_convert = {
            'add': dp.ofproto.OFPFC_ADD,
            'modify': dp.ofproto.OFPFC_MODIFY,
            'modify_strict': dp.ofproto.OFPFC_MODIFY_STRICT,
            'delete': dp.ofproto.OFPFC_DELETE,
            'delete_strict': dp.ofproto.OFPFC_DELETE_STRICT,
        }

        mod_cmd = cmd_convert.get(cmd, None)
        if mod_cmd is None:
            raise CommandNotFoundError(cmd=cmd)

        ofctl.mod_flow_entry(dp, flow, mod_cmd)

    @command_method
    def delete_flow_entry(self, req, dp, ofctl, flow, **kwargs):
        if ofproto_v1_0.OFP_VERSION == dp.ofproto.OFP_VERSION:
            flow = {}
        else:
            flow = {'table_id': dp.ofproto.OFPTT_ALL}

        ofctl.mod_flow_entry(dp, flow, dp.ofproto.OFPFC_DELETE)

    @command_method
    def mod_meter_entry(self, req, dp, ofctl, meter, cmd, **kwargs):
        cmd_convert = {
            'add': dp.ofproto.OFPMC_ADD,
            'modify': dp.ofproto.OFPMC_MODIFY,
            'delete': dp.ofproto.OFPMC_DELETE,
        }
        mod_cmd = cmd_convert.get(cmd, None)
        if mod_cmd is None:
            raise CommandNotFoundError(cmd=cmd)

        ofctl.mod_meter_entry(dp, meter, mod_cmd)

    @command_method
    def mod_group_entry(self, req, dp, ofctl, group, cmd, **kwargs):
        cmd_convert = {
            'add': dp.ofproto.OFPGC_ADD,
            'modify': dp.ofproto.OFPGC_MODIFY,
            'delete': dp.ofproto.OFPGC_DELETE,
        }
        mod_cmd = cmd_convert.get(cmd, None)
        if mod_cmd is None:
            raise CommandNotFoundError(cmd=cmd)

        ofctl.mod_group_entry(dp, group, mod_cmd)

    @command_method
    def mod_port_behavior(self, req, dp, ofctl, port_config, cmd, **kwargs):
        port_no = port_config.get('port_no', None)
        port_no = int(str(port_no), 0)

        port_info = self.dpset.port_state[int(dp.id)].get(port_no)
        if port_info:
            port_config.setdefault('hw_addr', port_info.hw_addr)
            if dp.ofproto.OFP_VERSION < ofproto_v1_4.OFP_VERSION:
                port_config.setdefault('advertise', port_info.advertised)
            else:
                port_config.setdefault('properties', port_info.properties)
        else:
            raise PortNotFoundError(port_no=port_no)

        if cmd != 'modify':
            raise CommandNotFoundError(cmd=cmd)

        ofctl.mod_port_behavior(dp, port_config)

    @command_method
    def send_experimenter(self, req, dp, ofctl, exp, **kwargs):
        ofctl.send_experimenter(dp, exp)

    @command_method
    def set_role(self, req, dp, ofctl, role, **kwargs):
        ofctl.set_role(dp, role)

    def set_ip_black_list(self, req, **_kwargs):
        # A = sensor_name
        # B = mac_address
        # C = ip
        # D = counter_packet
        # E = host_name
        # F = crypt
        # G = access
        sensor = Sensor.get_sensor_by_id(req.json_body['id'])
        if sensor == None:

            
            data = {'access': False}
            body = json.dumps(data)
        else:
        
            sensor_name = req.json_body['A']
            mac_address = req.json_body['B']
            ip = req.json_body['C']
            counter_packet = req.json_body['D']
            host_name = req.json_body['E']
            validate_sensor = sensor.validate_sensor(sensor_name, mac_address, counter_packet, host_name)                  
            if validate_sensor:
                if ip not in StatsController.list_ip_deny:
                    StatsController.list_ip_deny[ip] = True
                    data = {'G': True,
                    'D' : sensor.add_conter()}
                    body = json.dumps(data)
                    print("\033[2;31;43m",ip," detected!!!","\033[0;0m")
        return Response(content_type='application/json', body=body)

    def get_parameter(self, req, **_kwargs):

        key, iv , id = Sensor.request_sensors(req.json_body['sensor'],
                                              req.json_body['senha'],
                                              req.json_body['mac_address'],
                                              req.json_body['host_name'])
        if (key == ""):
            data = {'access': False}
        else:
            dps = list(self.dpset.dps.keys())
            data = {'access': True,
                    'id': id ,
                    'dpid': dps}
        body = json.dumps(data)
        return Response(content_type='application/json', body=body)
 

logger = logging.getLogger(__file__)
formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s')
logger.propagate = False
logger.setLevel(logging.INFO)

if not logger.handlers:
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

def _load_config_file():
    try:
        with open(cfg.CONF['test-switch']['dir']) as file_handler:
            return json.load(file_handler)
    except:
        return json.load(sys.stdin)



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.matchs = []
        self.datapath= None
        self.mac_to_port = {}

        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper

        wsgi.registory['StatsController'] = self.data
        path = '/stats'

        uri = path + '/switches/'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_dpids',
                       conditions=dict(method=['POST']))

        uri = path + '/desc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_desc_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/flowdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/flow/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/aggregateflow/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController,
                       action='get_aggregate_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/table/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_table_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/tablefeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_table_features',
                       conditions=dict(method=['GET']))

        uri = path + '/port/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/port/{dpid}/{port}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queue/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queue/{dpid}/{port}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queue/{dpid}/{port}/{queue_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queueconfig/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_config',
                       conditions=dict(method=['GET']))

        uri = path + '/queueconfig/{dpid}/{port}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_config',
                       conditions=dict(method=['GET']))

        uri = path + '/queuedesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/queuedesc/{dpid}/{port}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/queuedesc/{dpid}/{port}/{queue}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/meterfeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_features',
                       conditions=dict(method=['GET']))

        uri = path + '/meterconfig/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_config',
                       conditions=dict(method=['GET']))

        uri = path + '/meterconfig/{dpid}/{meter_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_config',
                       conditions=dict(method=['GET']))

        uri = path + '/meterdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/meterdesc/{dpid}/{meter_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/meter/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/meter/{dpid}/{meter_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/groupfeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_features',
                       conditions=dict(method=['GET']))

        uri = path + '/groupdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/groupdesc/{dpid}/{group_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/group/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/group/{dpid}/{group_id}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/portdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/portdesc/{dpid}/{port_no}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/role/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_role',
                       conditions=dict(method=['GET']))

        uri = path + '/flowentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_flow_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/flowentry/clear/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='delete_flow_entry',
                       conditions=dict(method=['DELETE']))

        uri = path + '/meterentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_meter_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/groupentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_group_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/portdesc/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_port_behavior',
                       conditions=dict(method=['POST']))

        uri = path + '/experimenter/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='send_experimenter',
                       conditions=dict(method=['POST']))

        uri = path + '/role'
        mapper.connect('stats', uri,
                       controller=StatsController, action='set_role',
                       conditions=dict(method=['POST']))

        # uri = path + '/black_list/{ip}'
        # mapper.connect('stats', uri,
        #                controller=StatsController, action='set_ip_black_list',
        #                conditions=dict(method=['POST']))
        uri = path + '/black_list/'
        mapper.connect('stats', uri,
                       controller=StatsController, action='set_ip_black_list',
                       conditions=dict(method=['POST']))

        uri = path + '/parameter/'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_parameter',
                       conditions=dict(method=['POST']))

        # /////
        self.datapaths = {}

        usr_config = _load_config_file()
        self.cookie_value = 0
        self._ip_origem = ""
        self._switch_mac_address = usr_config["service_mac"]
        self._switch_principal_ip = usr_config["service_ips"]["principal"]
        self._switch_secundario_ip = usr_config["service_ips"]["secundario"]

        self._principal_servers_ip = usr_config["server_ips"]["principal"]
        self._secundario_servers_ip = usr_config["server_ips"]["secundario"]

        self._client_ip_mac_mapping = dict()
        self._mac_port_mapping = dict()
        self._server_ip_mac_mapping = dict()
        self.__number_passwd = usr_config["number_password"]
        self._list_name_mac_sensors = usr_config["sensors"]
        self.__is_passwd = eval(usr_config["fixe_passwd"])
        self.__passwd = usr_config["passwd"]

        # create list objet sensor
        for sensor in self._list_name_mac_sensors:
            sensor_mac = usr_config["sensors_refence"][sensor]
            crypto = Cryptography()
            Sensor.sensors_list_map.append(Sensor(sensor, sensor_mac, self.__number_passwd,
                                                  crypto.Create_key(), crypto.Create_IV(),
                                                  self.__is_passwd, self.__passwd))

        for ip_address in self._principal_servers_ip + self._secundario_servers_ip:
            self._server_ip_mac_mapping[ip_address] = None

        self.select_balance = True

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath

        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]


        self.add_flow(self.datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=self.datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=self.datapath, priority=priority,
                                    match=match, instructions=inst)



        self.datapath.send_msg(mod)

    def del_flow(self, srcip,dstip):

        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=srcip,
                                ipv4_dst=dstip
                                )

        mod = parser.OFPFlowMod(datapath=self.datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        self.datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        self.datapath = msg.datapath
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = self.datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        ip1 = pkt.get_protocol(ipv4.ipv4)
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=srcip,
                                        ipv4_dst=dstip
                                        )
                self.matchs.append([srcip,dstip])
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(self.datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(self.datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=self.datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        self.datapath.send_msg(out)

class Cryptography:

    def Create_key(self):
        return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))

    def Create_IV(self):
        return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(16))

    @staticmethod
    def Encrypt(vkey, viv,  text_plane):
        iv = bytes(viv, 'UTF-8')
        key = bytes(vkey, 'UTF-8')
        text = bytes(text_plane, 'utf-8')
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ct_bytes = cipher.encrypt(text)

        return b64encode(ct_bytes).decode('utf-8')

    @staticmethod
    def Decrypt(vkey, viv, encoded_message):
        iv = bytes(viv, 'UTF-8')
        key = bytes(vkey, 'UTF-8')
        ct = b64decode(encoded_message)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        pt = cipher.decrypt(ct)
        return pt.decode('utf-8')

class Sensor:
    conter_id = 0
    sensors_list_map = []
    def __init__(self, sensor_nome, sensor_mac, number_caracter, sensor_key, sensor_iv,is_passwd,passwd):
        self.__sensor_id = Sensor.conter_id
        self.__sensor_nome = sensor_nome
        self.__sensor_mac = sensor_mac
        self.__is_passwd = is_passwd
        self.__passwd = passwd
        self.__sensor_password = self.Generate_password(number_caracter)
        self.__sensor_key = sensor_key
        self.__sensor_iv = sensor_iv
        self.__connected = False
        self.__conter_packet = 0
        self.__hostname = ""
        Sensor.conter_id += 1


    @staticmethod
    def request_sensors(_sensor, _passwd, _mac_address,host_name):
        key, iv,id = "", "", ""
        for sensor in Sensor.sensors_list_map:
            if (sensor.get_sensor_nome() == _sensor and sensor.get_sensor_password() == _passwd and sensor.get_sensor_mac() == _mac_address and not sensor.get_connected()):
                key = sensor.get_sensor_key()
                iv = sensor.get_sensor_iv()
                id = sensor.get_sensor_id()
                sensor.set_connected(True)
                sensor.set_hostname(host_name)
        return key, iv, id


    def validate_sensor(self,sensor_name,mac_address,counter_packet,host_name):
     
        if(self.__sensor_nome == sensor_name and self.__sensor_mac == mac_address and
                self.__conter_packet == counter_packet  and self.__hostname == host_name):
            return True
        else:
            return False

    def get_hostname(self):
        return self.__hostname

    def set_hostname(self, _hostname):
        self.__hostname = _hostname

    def get_sensor_id(self):
        return self.__sensor_id

    def add_conter(self):       
        self.__conter_packet += 1
        return self.__conter_packet

    def get_connected(self):
        return self.__connected

    def set_connected(self, _connected):
        self.__connected = _connected

    def get_sensor_nome(self):
        return self.__sensor_nome

    def set_sensor_nome(self, _sensor_nome):
        self.__sensor_nome = _sensor_nome


    def get_sensor_mac(self):
        return self.__sensor_mac

    def set_sensor_mac(self, _sensor_mac):
        self.__sensor_mac = _sensor_mac


    def get_sensor_password(self):
        return self.__sensor_password

    def set_sensor_password(self, _sensor_password):
        self.__sensor_password = _sensor_password


    def get_sensor_key(self):
        return self.__sensor_key

    def set__sensor_key(self, _sensor_key):
        self.__sensor_key = _sensor_key

    def get_sensor_iv(self):
        return self.__sensor_iv

    def set_sensor_iv(self, _sensor_iv):
        self.__sensor_iv = _sensor_iv

    def get_sensor_by_id(id):
        for sensor in Sensor.sensors_list_map:
            if sensor.get_sensor_id() == id:
                return sensor
        return None

    def Generate_password(self, number_caracter):

        if bool(self.__is_passwd):
            return self.__passwd
        else:
            letters = string.ascii_lowercase
            return ''.join(random.choice(letters) for i in range(number_caracter))

    def get_sensor(self):
        return 'ID Sensor >> {0} Sensor Name >> {1} - MAC Address >> {2} - Password >> {3} - Sensor Key >> {4} - Sensor IV >> {5}'.format(self.__sensor_id,
            self.__sensor_nome, self.__sensor_mac, self.__sensor_password, self.__sensor_key, self.__sensor_iv)


