# -*- coding: utf-8 -*-
# Description: python.d chart for basic monitoring of local host cockroachdb
# Author: Romolo Almeida (github:romol0s)
# SPDX-License-Identifier: GPL-3.0-or-later

import ssl, urllib2, string, socket, sys
from bases.FrameworkServices.SimpleService import SimpleService

ssl._create_default_https_context = ssl._create_unverified_context

priority = 90000

CHARTS = {
    'node_uptime': {
        'options': [None, 'Node up time', 'seconds', 'node', 'node', 'line'],
        'lines': [
            ['UpTime','seconds','absolute',1,1],
        ]
    }, 
    'liveness_livenodes': {
        'options': [None, 'Liveness Livenodes', 'count', 'node', 'node', 'line'],
        'lines': [
            ['LivenessLivenodes','count','absolute',1,1],
            ['LivenessLivenodesDeviation','deviation','incremental',1,1],
        ]
    }, 
    'clock_offset': {
        'options': [None, 'Clock offset', 'milliseconds', 'node', 'node', 'line'],
        'lines': [
            ['ClockOffsetMilliseconds','milliseconds','absolute',1,1],
            ['ClockOffsetStddevMilliseconds','deviation','absolute',1,1],
        ]
    }, 
    'store_capacity': {
        'options': [None, 'Store Capacity Usage', 'megabytes', 'store', 'store', 'line'],
        'lines': [
            ['CapacityAvailable','available','absolute',1,1024*1024],
            ['CapacityTotal','total','absolute',1,1024*1024],
            ['CapacityUsed','used','absolute',1,1024*1024],
        ]
    }, 
    'store_usage': {
        'options': [None, 'Store Capacity Usage', 'percentual', 'store', 'store', 'line'],
        'lines': [
            ['CapacityUsedPercent','used','absolute',1,1],
        ]
    },
    'memory_allocated': {
        'options': [None, 'Memory Allocated', 'megabytes', 'store', 'store', 'line'],
        'lines': [
            ['SysGoAllocbytes','sys_go_alloc','absolute',1,1024*1024],
            ['SysGoTotalbytes','sys_go_total','absolute',1,1024*1024],
            ['SysCgoTotalbytes','sys_cgo_total','absolute',1,1024*1024],
            ['SysCgoAllocbytes','sys_cgo_allocbytes','absolute',1,1024*1024],
        ]
    },
    'store_allocated': {
        'options': [None, 'Store Byte Allocation', 'megabytes', 'store', 'store', 'line'],
        'lines': [
            ['Totalbytes','totalbytes','absolute',1,1024*1024],
            ['Livebytes','livebytes','absolute',1,1024*1024],
            ['Valbytes','valbytes','absolute',1,1024*1024],
            ['Keybytes','keybytes','absolute',1,1024*1024],
        ]
    },
    'store_cache': {
        'options': [None, 'Store Cache', 'megabytes', 'store', 'store', 'line'],
        'lines': [
            ['RocksdbBlockCacheUsage','rocksdb_block_cache','absolute',1,1024*1024],
            ['RaftEntrycacheBytes','raft_entrycache','absolute',1,1024*1024],
        ]
    },
    'failures': {
        'options': [None, 'Failures', 'count', 'failures', 'failures', 'line'],
        'lines': [
            ['LivenessHeartbeatFailures','liveness_heartbeat','incremental',1,1],
            ['QueueReplicagcProcessFailure','queue_replicagc_process','incremental',1,1],
            ['GossipConnectionsRefused','gossip_connections_refused','incremental',1,1],
            ['QueueGcProcessFailure','queue_gc_process','incremental',1,1],
            ['QueueRaftlogProcessFailure','queue_raftlog_process','incremental',1,1],
        ]
    },
    'queue_pending': {
        'options': [None, 'Queue Pendings', 'count', 'queue', 'queue', 'line'],
        'lines': [
            ['QueueReplicatePending', 'replicate','absolute',1,1],
            ['QueueRaftsnapshotPending', 'raftsnapshot','absolute',1,1],
            ['QueueReplicagcPending', 'replicagc','absolute',1,1],
            ['QueueSplitPending', 'split','absolute',1,1],
            ['QueueMergePending', 'merge','absolute',1,1],
            ['QueueGcPending', 'gc','absolute',1,1],
            ['QueueRaftlogPending', 'raftlog','absolute',1,1],
        ]
    },
    'ranges_problems': {
        'options': [None, 'Ranges Problems', 'percentual', 'ranges', 'ranges', 'line'],
        'lines': [
            ['RangesUnavailablePercent','unavailable','percentage-of-absolute-row',1,1],
            ['RangesUnderreplicatedPercent','underreplicated','percentage-of-absolute-row',1,1],
        ]
    },
    'ranges': {
        'options': [None, 'Ranges', 'percentual', 'ranges', 'ranges', 'line'],
        'lines': [
            ['RangesTotal','total','absolute',1,1],
            ['RangesUnavailable','unavailable','absolute',1,1],
            ['RangesUnderreplicated','underreplicated','absolute',1,1],
        ]
    },
    'sql_connections': {
        'options': [None, 'Number of active sql connections', 'count', 'sql_statements', 'sql', 'line'],
        'lines': [
            ['SqlConnections','connections','absolute',1,1],
        ]
    }, 
    'sql_statements_per_second': {
        'options': [None, 'SQL Statements per seconds', 'count', 'sql_statements', 'sql', 'line'],
        'lines': [
            ['SqlDeleteCount','delete','incremental',1,5],
            ['SqlInsertCount','insert','incremental',1,5],
            ['SqlSelectCount','select','incremental',1,5],
            ['SqlUpdateCount','update','incremental',1,5],
            ['SqlTotalCount','total','incremental',1,5],
            ['SqlTxAbortCount','txn_abort','incremental',1,5],
            ['SqlFailureCount','failures','incremental',1,5],
        ]
    },
    'sql_statements_distribution': {
        'options': [None, 'SQL Statements Distribution (%)', 'percentual', 'sql_statements', 'sql', 'line'],
        'lines': [
            ['SqlDeleteDistribution','delete','percentage-of-incremental-row',1,1],
            ['SqlInsertDistribution','insert','percentage-of-incremental-row',1,1],
            ['SqlSelectDistribution','select','percentage-of-incremental-row',1,1],
            ['SqlUpdateDistribution','update','percentage-of-incremental-row',1,1],
        ]
    },
}

ORDER = [ x[0] for x in sorted( CHARTS.items(), key=lambda x: x[1] ) ]

def get_tcp_ip_by_port(SearchPort):
    IpList = []
    for Line in [ l.strip() for l in open('/proc/net/tcp','r').readlines() ]:
        HexaLocalAddress = Line.split()[1]
        HexaRemoteAddress = Line.split()[2]
        if HexaRemoteAddress == '00000000:0000':
            HexaAddress, HexaPort = HexaLocalAddress.split(':')
            TcpPort = int(HexaPort,16)
            if TcpPort == SearchPort:
                IpList.append(''.join([ 
                    str(int(HexaAddress[6:8],16)), '.',
                    str(int(HexaAddress[4:6],16)), '.', 
                    str(int(HexaAddress[2:4],16)), '.', 
                    str(int(HexaAddress[0:2],16)),
                    ])
                )
    return IpList

def get_vars():
    global url_vars
    try:
        try:
            request = urllib2.Request( ''.join(['http://',url]) )
            request.add_header('User-Agent', "Mozilla/5.0")
            request.add_header('Cache-Control', "no-cache")
            url_vars = urllib2.urlopen( request )   
        except:
            request = urllib2.Request( ''.join(['https://',url]) )
            request.add_header('User-Agent', "Mozilla/5.0")
            request.add_header('Cache-Control', "no-cache")
            context = ssl._create_unverified_context()
            url_vars = urllib2.urlopen( request, context = context )   
    except Exception as e:
        print ''.join(['Failed on connect to "',url,'" using http or https.'])
        print e
        sys.exit(1)


class Service(SimpleService):

    def __init__(self, configuration=None, name=None):
        SimpleService.__init__(self, configuration=configuration, name=name)
        self.order = ORDER
        self.definitions = CHARTS

    @staticmethod
    def check():
        global url
        ips_port_26257 = get_tcp_ip_by_port(26257)
        ips_port_8080 = get_tcp_ip_by_port(8080)
        if len(ips_port_26257) > 0 and len(ips_port_8080) :
            url = ''.join([ips_port_8080[0],':8080/_status/vars'])
            return True
        return False

    def get_data(self):
        global url_vars
        data = dict()
        get_vars()
        for line in [ l.strip() for l in sorted(url_vars.readlines()) if l[0:1] != '#']:
            if "}" in line:
                parametername = string.lower(line.split('{')[0])
                parametervalue = line.split()[1].split('}')[0]
            else:
                parametername = line.split()[0]
                parametervalue = line.split()[1]
            exec("%s = float(%s)" % (parametername,parametervalue))
        data['CapacityUsedPercent'] = round(capacity_used / ( capacity_available + capacity_used ) * 100, 2)
        data['ClockOffsetMilliseconds'] = clock_offset_meannanos * 1e-6
        data['ClockOffsetStddevMilliseconds'] = clock_offset_stddevnanos * 1e-6
        data['GossipConnectionsRefused'] = gossip_connections_refused
        data['Keybytes'] = keybytes
        data['Livebytes'] = livebytes
        data['LivenessHeartbeatFailures'] = liveness_heartbeatfailures
        data['LivenessLivenodes'] = liveness_livenodes
        data['LivenessLivenodesDeviation'] = liveness_livenodes
        data['QueueGcPending'] = queue_gc_pending
        data['QueueGcProcessFailure'] = queue_gc_process_failure
        data['QueueMergePending'] = queue_merge_pending
        data['QueueRaftlogPending'] = queue_raftlog_pending
        data['QueueRaftlogProcessFailure'] = queue_raftlog_process_failure
        data['QueueRaftsnapshotPending'] = queue_raftsnapshot_pending
        data['QueueReplicagcPending'] = queue_replicagc_pending
        data['QueueReplicagcProcessFailure'] = queue_replicagc_process_failure
        data['QueueReplicatePending'] = queue_replicate_pending
        data['QueueSplitPending'] = queue_split_pending
        data['RaftEntrycacheBytes'] = raft_entrycache_bytes
        data['RangesTotal'] = ranges
        data['RangesUnavailable'] = ranges_unavailable
        data['RangesUnderreplicated'] = ranges_underreplicated
        data['RangesUnavailablePercent'] = ranges_unavailable
        data['RangesUnderreplicatedPercent'] = ranges_underreplicated
        data['RocksdbBlockCacheUsage'] = rocksdb_block_cache_usage
        data['SqlConnections'] = sql_conns
        data['SqlDeleteCount'] = sql_delete_count
        data['SqlDeleteDistribution'] = sql_delete_count
        data['SqlFailureCount'] = sql_failure_count
        data['SqlInsertCount'] = sql_insert_count
        data['SqlInsertDistribution'] = sql_insert_count
        data['SqlSelectCount'] = sql_select_count
        data['SqlSelectDistribution'] = sql_delete_count
        data['SqlTotalCount'] = sql_delete_count + sql_insert_count + sql_query_count + sql_update_count
        data['SqlTxAbortCount'] = sql_txn_abort_count 
        data['SqlUpdateCount'] = sql_update_count
        data['SqlUpdateDistribution'] = sql_update_count
        data['SysCgoAllocbytes'] = sys_cgo_allocbytes
        data['SysCgoTotalbytes'] = sys_cgo_totalbytes
        data['SysGoAllocbytes'] = sys_go_allocbytes
        data['SysGoTotalbytes'] = sys_go_totalbytes
        data['Totalbytes'] = totalbytes
        data['UpTime'] = int(sys_uptime)
        data['Valbytes'] = valbytes
        return data
