{
  "ServiceProbes": [
    {
      "Service": "MySQL",
      "DefaultPort": 3306,
      "Probes": [
        {
          "Description": "MySQL Handshake",
          "Send": {
            "HexString": "200000018521000000000000000000000000000000000000000000000000000000000000000000000000",
            "Explanation": "Client handshake initialization packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^.\\x00\\x00\\x00\\x0a(5\\.|8\\.)",
              "Indicates": "MySQL server version"
            },
            {
              "Pattern": "mysql_native_password",
              "Indicates": "MySQL with native auth"
            },
            {
              "Pattern": "caching_sha2_password",
              "Indicates": "MySQL with SHA2 auth"
            }
          ]
        }
      ]
    },
    {
      "Service": "MariaDB",
      "DefaultPort": 3306,
      "Probes": [
        {
          "Description": "MariaDB Handshake",
          "Send": {
            "HexString": "200000018521000000000000000000000000000000000000000000000000000000000000000000000000",
            "Explanation": "Client handshake initialization packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "mariadb",
              "Indicates": "MariaDB server"
            }
          ]
        }
      ]
    },
    {
      "Service": "PostgreSQL",
      "DefaultPort": 5432,
      "Probes": [
        {
          "Description": "PostgreSQL Startup",
          "Send": {
            "HexString": "000000080000000400000000",
            "Explanation": "SSL request packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^S",
              "Indicates": "PostgreSQL with SSL"
            },
            {
              "Pattern": "^N",
              "Indicates": "PostgreSQL without SSL"
            }
          ]
        },
        {
          "Description": "PostgreSQL Version Query",
          "Send": {
            "HexString": "00000021000300007573657200706F737467726573000000",
            "Explanation": "Version query packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "PostgreSQL",
              "Indicates": "PostgreSQL version info"
            }
          ]
        }
      ]
    },
    {
      "Service": "MongoDB",
      "DefaultPort": 27017,
      "Probes": [
        {
          "Description": "MongoDB isMaster",
          "Send": {
            "HexString": "3900000000000000000000000000FFFFFFFF430000000000000000000100000000000000696E7465726E616C2E69734D6173746572000000000000F03F00",
            "Explanation": "Binary message requesting isMaster status"
          },
          "ExpectedResponses": [
            {
              "Pattern": "\"ismaster\" : true",
              "Indicates": "MongoDB primary"
            },
            {
              "Pattern": "\"ismaster\" : false",
              "Indicates": "MongoDB secondary"
            }
          ]
        },
        {
          "Description": "MongoDB Server Status",
          "Send": {
            "HexString": "4300000002000000000000000000FFFFFFFF440000000000000000000100000000000000616464696E676F2E73657276657253746174757300000000000000F03F00",
            "Explanation": "Binary message requesting server status"
          },
          "ExpectedResponses": [
            {
              "Pattern": "\"version\":",
              "Indicates": "MongoDB server status"
            }
          ]
        }
      ]
    },
    {
      "Service": "Redis",
      "DefaultPort": 6379,
      "Probes": [
        {
          "Description": "Redis INFO Command",
          "Send": "*1\r\n$4\r\nINFO\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "redis_version:",
              "Indicates": "Redis server"
            }
          ]
        },
        {
          "Description": "Redis PING",
          "Send": "*1\r\n$4\r\nPING\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "+PONG",
              "Indicates": "Redis server responding"
            }
          ]
        },
        {
          "Description": "Redis Role Check",
          "Send": "*1\r\n$4\r\nROLE\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "*3\r\n+master",
              "Indicates": "Redis master"
            },
            {
              "Pattern": "*5\r\n+slave",
              "Indicates": "Redis replica"
            }
          ]
        }
      ]
    },
    {
      "Service": "Cassandra",
      "DefaultPort": 9042,
      "Probes": [
        {
          "Description": "Cassandra CQL Protocol",
          "Send": {
            "HexString": "040000000B00000000",
            "Explanation": "CQL protocol version negotiation"
          },
          "ExpectedResponses": [
            {
              "Pattern": "\\x04\\x00\\x00\\x00\\x00",
              "Indicates": "Cassandra CQL response"
            }
          ]
        }
      ]
    },
    {
      "Service": "CouchDB",
      "DefaultPort": 5984,
      "Probes": [
        {
          "Description": "CouchDB Info",
          "Send": "GET / HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"couchdb\":\"Welcome\"",
              "Indicates": "CouchDB server"
            }
          ]
        },
        {
          "Description": "CouchDB Version",
          "Send": "GET /_utils HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Fauxton",
              "Indicates": "CouchDB Fauxton interface"
            }
          ]
        }
      ]
    },
    {
      "Service": "Neo4j",
      "DefaultPort": 7687,
      "Probes": [
        {
          "Description": "Neo4j Bolt Protocol",
          "Send": {
            "HexString": "6060B017",
            "Explanation": "Bolt protocol handshake"
          },
          "ExpectedResponses": [
            {
              "Pattern": "\\x00\\x00\\x00\\x01",
              "Indicates": "Neo4j Bolt protocol"
            }
          ]
        }
      ]
    },
    {
      "Service": "InfluxDB",
      "DefaultPort": 8086,
      "Probes": [
        {
          "Description": "InfluxDB Ping",
          "Send": "GET /ping HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "X-Influxdb-Version:",
              "Indicates": "InfluxDB server"
            }
          ]
        },
        {
          "Description": "InfluxDB Health",
          "Send": "GET /health HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"status\":\"pass\"",
              "Indicates": "InfluxDB healthy"
            }
          ]
        }
      ]
    },
    {
      "Service": "Elasticsearch",
      "DefaultPort": 9200,
      "Probes": [
        {
          "Description": "Elasticsearch Info",
          "Send": "GET / HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"cluster_name\"\\s*:",
              "Indicates": "Elasticsearch node"
            },
            {
              "Pattern": "\"version\"\\s*:\\s*{\\s*\"number\"\\s*:",
              "Indicates": "Elasticsearch with version info"
            }
          ]
        },
        {
          "Description": "Elasticsearch Health",
          "Send": "GET /_cluster/health HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"status\":\\s*(\"green\"|\"yellow\"|\"red\")",
              "Indicates": "Elasticsearch cluster health"
            }
          ]
        },
        {
          "Description": "Elasticsearch Stats",
          "Send": "GET /_stats HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"_all\":",
              "Indicates": "Elasticsearch stats"
            }
          ]
        }
      ]
    },
    {
      "Service": "SSH",
      "DefaultPort": 22,
      "Probes": [
        {
          "Description": "SSH Version",
          "Send": "SSH-2.0-OpenSSH_8.1\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^SSH-2\\.0-OpenSSH_",
              "Indicates": "OpenSSH server"
            },
            {
              "Pattern": "^SSH-2\\.0-Dropbear",
              "Indicates": "Dropbear SSH server"
            },
            {
              "Pattern": "^SSH-2\\.0-PuTTY",
              "Indicates": "PuTTY SSH server"
            },
            {
              "Pattern": "^SSH-2\\.0-WeOnlyDo",
              "Indicates": "WinSSHD server"
            },
            {
              "Pattern": "^SSH-2\\.0-BitVise",
              "Indicates": "BitVise SSH server"
            }
          ]
        }
      ]
    },
    {
      "Service": "LDAP",
      "DefaultPort": 389,
      "Probes": [
        {
          "Description": "LDAP Search Request",
          "Send": {
            "HexString": "300c02010160070201030400800000",
            "Explanation": "LDAP search request"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^0\\x84",
              "Indicates": "LDAP response"
            }
          ]
        },
        {
          "Description": "LDAP Root DSE",
          "Send": {
            "HexString": "301c0201016017020103040b6f626a656374436c61737330070a0100",
            "Explanation": "LDAP root DSE query"
          },
          "ExpectedResponses": [
            {
              "Pattern": "supportedLDAPVersion",
              "Indicates": "LDAP root DSE"
            }
          ]
        },
        {
          "Description": "LDAP Bind Request",
          "Send": {
            "HexString": "3034020101602f020103042B644e3d61646d696e2c64633d6578616d706c652c64633d636f6d",
            "Explanation": "LDAP anonymous bind request"
          },
          "ExpectedResponses": [
            {
              "Pattern": "\\x0a\\x01\\x00",
              "Indicates": "LDAP bind success"
            },
            {
              "Pattern": "\\x0a\\x01\\x31",
              "Indicates": "LDAP bind failure"
            }
          ]
        }
      ]
    },
    {
      "Service": "LDAPS",
      "DefaultPort": 636,
      "Probes": [
        {
          "Description": "LDAPS Handshake",
          "Send": {
            "HexString": "16030100bb010000b70303",
            "Explanation": "TLS 1.0 Client Hello for LDAPS"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x16\\x03",
              "Indicates": "LDAPS server"
            }
          ]
        }
      ]
    },
    {
      "Service": "SNMP",
      "DefaultPort": 161,
      "Probes": [
        {
          "Description": "SNMP GetRequest",
          "Send": {
            "HexString": "302602010004067075626c6963a019020400000000020100020100300b300906052b060102010500",
            "Explanation": "SNMP v1 get request with public community"
          },
          "ExpectedResponses": [
            {
              "Pattern": "\\x30.*\\x02\\x01.*\\x04",
              "Indicates": "SNMP response"
            }
          ]
        },
        {
          "Description": "SNMP v3 Probe",
          "Send": {
            "HexString": "3029020103300e020100020300ffe304010102010304010301040f30000400",
            "Explanation": "SNMPv3 get request"
          },
          "ExpectedResponses": [
            {
              "Pattern": "\\x30.*\\x02\\x01\\x03",
              "Indicates": "SNMPv3 agent"
            }
          ]
        }
      ]
    },
    {
      "Service": "NTP",
      "DefaultPort": 123,
      "Probes": [
        {
          "Description": "NTP Version Query",
          "Send": {
            "HexString": "1b00042a0000000000000000",
            "Explanation": "NTP version query"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x1c",
              "Indicates": "NTP server"
            }
          ]
        },
        {
          "Description": "NTP Control Query",
          "Send": {
            "HexString": "160200000000000000000000",
            "Explanation": "NTP control query"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x16",
              "Indicates": "NTP control response"
            }
          ]
        }
      ]
    },
    {
      "Service": "RADIUS",
      "DefaultPort": 1812,
      "Probes": [
        {
          "Description": "RADIUS Access Request",
          "Send": {
            "HexString": "01000014000000000000000000000000",
            "Explanation": "RADIUS access request packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x02",
              "Indicates": "RADIUS access reject"
            },
            {
              "Pattern": "^\\x03",
              "Indicates": "RADIUS access challenge"
            }
          ]
        }
      ]
    },
    {
      "Service": "RPC",
      "DefaultPort": 111,
      "Probes": [
        {
          "Description": "RPC Null Call",
          "Send": {
            "HexString": "80000028000000000000000000000002000186a0000000020000000000000000000000000000000000000000",
            "Explanation": "RPC null call"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x80\\x00\\x00",
              "Indicates": "RPC response"
            }
          ]
        }
      ]
    },
    {
      "Service": "IPMI",
      "DefaultPort": 623,
      "Probes": [
        {
          "Description": "IPMI Get Channel Auth",
          "Send": {
            "HexString": "0600ff07000000000000000000000000",
            "Explanation": "IPMI RMCP ping"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x06\\x00\\xff\\x07",
              "Indicates": "IPMI BMC"
            }
          ]
        }
      ]
    },
    {
      "Service": "Kerberos",
      "DefaultPort": 88,
      "Probes": [
        {
          "Description": "Kerberos AS-REQ",
          "Send": {
            "HexString": "6a81a53081a2a103020105a20302010aa30e300c300aa103020101a203020102a4818930818602018aa181800201ffa08102046b726274677430173015a003020101a10e040c4558414d504c452e434f4d6e82166c6f63616c686f73742e6c6f63616c646f6d61696ea481163014a003020101a10d040b41646d696e6973747261",
            "Explanation": "Kerberos AS-REQ packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x6a",
              "Indicates": "Kerberos KDC"
            }
          ]
        }
      ]
    },
    {
      "Service": "SMB",
      "DefaultPort": 445,
      "Probes": [
        {
          "Description": "SMB Negotiate Protocol",
          "Send": {
            "HexString": "000000a4ff534d4272000000001843c80000000000000000000000000000fffe00000000000000000000000000000000000000000000000000000000000000000024000500010000007f000000d95110535aafd5010000000000000000000000000000000000000000000000020002000100020003002e0002002e00",
            "Explanation": "SMBv2 negotiate protocol request"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x00\\x00.*\\xfe\\x53\\x4d\\x42",
              "Indicates": "SMB2 server"
            },
            {
              "Pattern": "^\\x00\\x00.*\\xff\\x53\\x4d\\x42",
              "Indicates": "SMB1 server"
            }
          ]
        }
      ]
    },
    {
      "Service": "IMAP",
      "DefaultPort": 143,
      "Probes": [
        {
          "Description": "IMAP Capability",
          "Send": "A001 CAPABILITY\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\\* CAPABILITY",
              "Indicates": "IMAP server capabilities"
            }
          ]
        }
      ]
    },
    {
      "Service": "POP3",
      "DefaultPort": 110,
      "Probes": [
        {
          "Description": "POP3 Capability",
          "Send": "CAPA\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\\+OK",
              "Indicates": "POP3 server capabilities"
            }
          ]
        }
      ]
    },
    {
      "Service": "HAProxy",
      "DefaultPort": 8000,
      "Probes": [
        {
          "Description": "HAProxy Stats Page",
          "Send": "GET /haproxy?stats HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "HAProxy Statistics",
              "Indicates": "HAProxy stats page"
            }
          ]
        },
        {
          "Description": "HAProxy Stats CSV",
          "Send": "GET /haproxy?stats;csv HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^# pxname,svname",
              "Indicates": "HAProxy CSV stats"
            }
          ]
        },
        {
          "Description": "HAProxy Info",
          "Send": "GET /info HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "HAProxy version",
              "Indicates": "HAProxy info page"
            }
          ]
        }
      ]
    },
    {
      "Service": "Traefik",
      "DefaultPort": 80,
      "Probes": [
        {
          "Description": "Traefik Dashboard",
          "Send": "GET /dashboard/ HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Traefik",
              "Indicates": "Traefik dashboard"
            }
          ]
        },
        {
          "Description": "Traefik API",
          "Send": "GET /api/version HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"Version\":",
              "Indicates": "Traefik API"
            }
          ]
        },
        {
          "Description": "Traefik Health",
          "Send": "GET /ping HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^ok$",
              "Indicates": "Traefik health check"
            }
          ]
        }
      ]
    },
    {
      "Service": "Envoy",
      "DefaultPort": 9901,
      "Probes": [
        {
          "Description": "Envoy Admin Interface",
          "Send": "GET /server_info HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "version",
              "Indicates": "Envoy admin interface"
            }
          ]
        },
        {
          "Description": "Envoy Stats",
          "Send": "GET /stats HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "cluster_manager",
              "Indicates": "Envoy stats"
            }
          ]
        },
        {
          "Description": "Envoy Clusters",
          "Send": "GET /clusters HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "cluster::",
              "Indicates": "Envoy clusters info"
            }
          ]
        }
      ]
    },
    {
      "Service": "OpenIG",
      "DefaultPort": 8080,
      "Probes": [
        {
          "Description": "OpenIG API",
          "Send": "GET /openig/api/system/info HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"version\":",
              "Indicates": "OpenIG API"
            }
          ]
        },
        {
          "Description": "OpenIG Routes",
          "Send": "GET /openig/api/routes HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"_id\":",
              "Indicates": "OpenIG routes API"
            }
          ]
        }
      ]
    },
    {
      "Service": "NGINX",
      "DefaultPort": 80,
      "Probes": [
        {
          "Description": "NGINX Status Page",
          "Send": "GET /nginx_status HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Active connections:",
              "Indicates": "NGINX status page"
            }
          ]
        },
        {
          "Description": "NGINX Server Header",
          "Send": "GET / HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Server: nginx",
              "Indicates": "NGINX server"
            }
          ]
        },
        {
          "Description": "NGINX Stub Status",
          "Send": "GET /stub_status HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "server accepts handled requests",
              "Indicates": "NGINX stub status"
            }
          ]
        }
      ]
    },
    {
      "Service": "Apache HTTP Server",
      "DefaultPort": 8080,
      "Probes": [
        {
          "Description": "Apache Status Page",
          "Send": "GET /server-status HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Apache Server Status",
              "Indicates": "Apache status page"
            }
          ]
        },
        {
          "Description": "Apache Server Header",
          "Send": "GET / HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Server: Apache",
              "Indicates": "Apache server"
            }
          ]
        },
        {
          "Description": "Apache Info Page",
          "Send": "GET /server-info HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Apache Server Information",
              "Indicates": "Apache info page"
            }
          ]
        }
      ]
    },
    {
      "Service": "Caddy",
      "DefaultPort": 8082,
      "Probes": [
        {
          "Description": "Caddy Status",
          "Send": "GET /status HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"version\":",
              "Indicates": "Caddy status page"
            }
          ]
        },
        {
          "Description": "Caddy Metrics",
          "Send": "GET /metrics HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "caddy_",
              "Indicates": "Caddy metrics"
            }
          ]
        },
        {
          "Description": "Caddy Admin",
          "Send": "GET /admin/config HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "admin endpoint",
              "Indicates": "Caddy admin interface"
            }
          ]
        }
      ]
    },
    {
      "Service": "RabbitMQ",
      "DefaultPort": 5672,
      "Probes": [
        {
          "Description": "AMQP Protocol Header",
          "Send": {
            "HexString": "414D515001000000",
            "Explanation": "AMQP protocol header"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^AMQP\\x00\\x00\\x09\\x01",
              "Indicates": "RabbitMQ AMQP 0-9-1"
            }
          ]
        }
      ]
    },
    {
      "Service": "Kafka",
      "DefaultPort": 9092,
      "Probes": [
        {
          "Description": "Kafka API Version Request",
          "Send": {
            "HexString": "0000002100000000000000000018000000000000096B61666B612D726571000000000000",
            "Explanation": "ApiVersions request"
          },
          "ExpectedResponses": [
            {
              "Pattern": "\\x00\\x00\\x00.*\\x00\\x00\\x00\\x00",
              "Indicates": "Kafka broker response"
            }
          ]
        }
      ]
    },
    {
      "Service": "Memcached",
      "DefaultPort": 11211,
      "Probes": [
        {
          "Description": "Memcached Version",
          "Send": "version\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^VERSION ",
              "Indicates": "Memcached server"
            }
          ]
        },
        {
          "Description": "Memcached Stats",
          "Send": "stats\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^STAT pid",
              "Indicates": "Memcached server stats"
            }
          ]
        }
      ]
    },
    {
      "Service": "FTP",
      "DefaultPort": 21,
      "Probes": [
        {
          "Description": "FTP Banner Grab",
          "Send": "USER anonymous\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^220",
              "Indicates": "FTP server ready"
            },
            {
              "Pattern": "^331",
              "Indicates": "FTP user OK, need password"
            }
          ]
        }
      ]
    },
    {
      "Service": "SMTP",
      "DefaultPort": 25,
      "Probes": [
        {
          "Description": "SMTP EHLO",
          "Send": "EHLO test\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^250",
              "Indicates": "SMTP server"
            }
          ]
        }
      ]
    },
    {
      "Service": "HTTP",
      "DefaultPort": 80,
      "Probes": [
        {
          "Description": "HTTP GET Request",
          "Send": "GET / HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^HTTP/1\\.",
              "Indicates": "HTTP server"
            }
          ]
        },
        {
          "Description": "HTTP OPTIONS",
          "Send": "OPTIONS / HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^HTTP/1\\.",
              "Indicates": "HTTP server with OPTIONS"
            }
          ]
        }
      ]
    },
    {
      "Service": "HTTPS",
      "DefaultPort": 443,
      "Probes": [
        {
          "Description": "TLS Client Hello",
          "Send": {
            "HexString": "16030100650100006103015",
            "Explanation": "TLS 1.0 Client Hello"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x16\\x03",
              "Indicates": "TLS/SSL server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Telnet",
      "DefaultPort": 23,
      "Probes": [
        {
          "Description": "Telnet IAC",
          "Send": {
            "HexString": "FFFB01",
            "Explanation": "Telnet WILL ECHO"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\xff",
              "Indicates": "Telnet server"
            }
          ]
        }
      ]
    },
    {
      "Service": "DNS",
      "DefaultPort": 53,
      "Probes": [
        {
          "Description": "DNS Query",
          "Send": {
            "HexString": "00000100000100000000000003777777076578616d706c6503636f6d0000010001",
            "Explanation": "DNS query for www.example.com"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x00\\x00.*\\x81\\x80",
              "Indicates": "DNS server response"
            }
          ]
        }
      ]
    },
    {
      "Service": "MQTT",
      "DefaultPort": 1883,
      "Probes": [
        {
          "Description": "MQTT Connect",
          "Send": {
            "HexString": "101600044d51545404020000000474657374",
            "Explanation": "MQTT CONNECT packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x20\\x02",
              "Indicates": "MQTT CONNACK"
            }
          ]
        }
      ]
    },
    {
      "Service": "VNC",
      "DefaultPort": 5900,
      "Probes": [
        {
          "Description": "VNC RFB Protocol",
          "Send": "RFB 003.008\n",
          "ExpectedResponses": [
            {
              "Pattern": "^RFB ",
              "Indicates": "VNC server"
            }
          ]
        }
      ]
    },
    {
      "Service": "RDP",
      "DefaultPort": 3389,
      "Probes": [
        {
          "Description": "RDP Connection Request",
          "Send": {
            "HexString": "030000130ee000000000000100080003000000",
            "Explanation": "RDP connection request"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x03\\x00\\x00",
              "Indicates": "RDP server"
            }
          ]
        }
      ]
    },
    {
      "Service": "RTSP",
      "DefaultPort": 554,
      "Probes": [
        {
          "Description": "RTSP OPTIONS",
          "Send": "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^RTSP/1\\.0",
              "Indicates": "RTSP server"
            }
          ]
        }
      ]
    },
    {
      "Service": "SIP",
      "DefaultPort": 5060,
      "Probes": [
        {
          "Description": "SIP OPTIONS",
          "Send": "OPTIONS sip:test@example.com SIP/2.0\r\nVia: SIP/2.0/UDP localhost:5060\r\nFrom: <sip:test@localhost>\r\nTo: <sip:test@localhost>\r\nCall-ID: test@localhost\r\nCSeq: 1 OPTIONS\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^SIP/2\\.0",
              "Indicates": "SIP server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Docker Registry",
      "DefaultPort": 5000,
      "Probes": [
        {
          "Description": "Docker Registry Version",
          "Send": "GET /v2/ HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Docker-Distribution-Api-Version",
              "Indicates": "Docker Registry"
            }
          ]
        }
      ]
    },
    {
      "Service": "Kubernetes API",
      "DefaultPort": 6443,
      "Probes": [
        {
          "Description": "Kubernetes API Health",
          "Send": "GET /healthz HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^ok",
              "Indicates": "Kubernetes API server"
            }
          ]
        }
      ]
    },
    {
      "Service": "etcd",
      "DefaultPort": 2379,
      "Probes": [
        {
          "Description": "etcd Version",
          "Send": "GET /version HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"etcdserver\":",
              "Indicates": "etcd server"
            }
          ]
        },
        {
          "Description": "etcd Health",
          "Send": "GET /health HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"health\":",
              "Indicates": "etcd health status"
            }
          ]
        }
      ]
    },
    {
      "Service": "Consul",
      "DefaultPort": 8500,
      "Probes": [
        {
          "Description": "Consul API Version",
          "Send": "GET /v1/status/leader HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": ":\\d+",
              "Indicates": "Consul server"
            }
          ]
        },
        {
          "Description": "Consul Health",
          "Send": "GET /v1/health/service/consul HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"ServiceName\":\"consul\"",
              "Indicates": "Consul health check"
            }
          ]
        }
      ]
    },
    {
      "Service": "Vault",
      "DefaultPort": 8200,
      "Probes": [
        {
          "Description": "Vault Health",
          "Send": "GET /v1/sys/health HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"initialized\":",
              "Indicates": "Vault server"
            }
          ]
        },
        {
          "Description": "Vault Seal Status",
          "Send": "GET /v1/sys/seal-status HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"sealed\":",
              "Indicates": "Vault seal status"
            }
          ]
        }
      ]
    },
    {
      "Service": "Prometheus",
      "DefaultPort": 9090,
      "Probes": [
        {
          "Description": "Prometheus Metrics",
          "Send": "GET /metrics HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "prometheus_",
              "Indicates": "Prometheus server"
            }
          ]
        },
        {
          "Description": "Prometheus API Status",
          "Send": "GET /api/v1/status/config HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"status\":\"success\"",
              "Indicates": "Prometheus API"
            }
          ]
        }
      ]
    },
    {
      "Service": "Grafana",
      "DefaultPort": 3000,
      "Probes": [
        {
          "Description": "Grafana API Health",
          "Send": "GET /api/health HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"database\":\"ok\"",
              "Indicates": "Grafana server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Jenkins",
      "DefaultPort": 8080,
      "Probes": [
        {
          "Description": "Jenkins API",
          "Send": "GET /api/json HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"mode\":\"NORMAL\"",
              "Indicates": "Jenkins server"
            },
            {
              "Pattern": "X-Jenkins:",
              "Indicates": "Jenkins header"
            }
          ]
        }
      ]
    },
    {
      "Service": "Tomcat",
      "DefaultPort": 8080,
      "Probes": [
        {
          "Description": "Tomcat Manager",
          "Send": "GET /manager/html HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Apache Tomcat",
              "Indicates": "Tomcat manager"
            }
          ]
        }
      ]
    },
    {
      "Service": "JBoss",
      "DefaultPort": 8080,
      "Probes": [
        {
          "Description": "JBoss Welcome Page",
          "Send": "GET / HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "JBoss",
              "Indicates": "JBoss server"
            }
          ]
        }
      ]
    },
    {
      "Service": "WebLogic",
      "DefaultPort": 7001,
      "Probes": [
        {
          "Description": "WebLogic Console",
          "Send": "GET /console HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "WebLogic",
              "Indicates": "WebLogic server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Zookeeper",
      "DefaultPort": 2181,
      "Probes": [
        {
          "Description": "Zookeeper stat",
          "Send": "stat\n",
          "ExpectedResponses": [
            {
              "Pattern": "Zookeeper version:",
              "Indicates": "Zookeeper server"
            }
          ]
        },
        {
          "Description": "Zookeeper ruok",
          "Send": "ruok\n",
          "ExpectedResponses": [
            {
              "Pattern": "^imok",
              "Indicates": "Zookeeper responding"
            }
          ]
        }
      ]
    },
    {
      "Service": "MinIO",
      "DefaultPort": 9000,
      "Probes": [
        {
          "Description": "MinIO Health",
          "Send": "GET /minio/health/live HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^HTTP/1\\.. 200",
              "Indicates": "MinIO server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Apache Solr",
      "DefaultPort": 8983,
      "Probes": [
        {
          "Description": "Solr Admin",
          "Send": "GET /solr/admin/info/system HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"lucene\":",
              "Indicates": "Apache Solr"
            }
          ]
        }
      ]
    },
    {
      "Service": "RethinkDB",
      "DefaultPort": 28015,
      "Probes": [
        {
          "Description": "RethinkDB Protocol",
          "Send": {
            "HexString": "c3bdc234",
            "Explanation": "RethinkDB protocol version"
          },
          "ExpectedResponses": [
            {
              "Pattern": "SUCCESS",
              "Indicates": "RethinkDB server"
            }
          ]
        }
      ]
    },
    {
      "Service": "ArangoDB",
      "DefaultPort": 8529,
      "Probes": [
        {
          "Description": "ArangoDB Version",
          "Send": "GET /_api/version HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"server\":\"arango\"",
              "Indicates": "ArangoDB server"
            }
          ]
        }
      ]
    },
    {
      "Service": "OrientDB",
      "DefaultPort": 2424,
      "Probes": [
        {
          "Description": "OrientDB Binary Protocol",
          "Send": {
            "HexString": "0100",
            "Explanation": "OrientDB protocol handshake"
          },
          "ExpectedResponses": [
            {
              "Pattern": "OrientDB",
              "Indicates": "OrientDB server"
            }
          ]
        }
      ]
    },
    {
      "Service": "ClickHouse",
      "DefaultPort": 9000,
      "Probes": [
        {
          "Description": "ClickHouse Native Protocol",
          "Send": {
            "HexString": "00",
            "Explanation": "ClickHouse hello packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "ClickHouse",
              "Indicates": "ClickHouse server"
            }
          ]
        }
      ]
    },
    {
      "Service": "TimescaleDB",
      "DefaultPort": 5432,
      "Probes": [
        {
          "Description": "PostgreSQL with TimescaleDB",
          "Send": {
            "HexString": "000000080000000400000000",
            "Explanation": "SSL request packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^S",
              "Indicates": "PostgreSQL (potentially TimescaleDB)"
            },
            {
              "Pattern": "^N",
              "Indicates": "PostgreSQL (potentially TimescaleDB)"
            }
          ]
        }
      ]
    },
    {
      "Service": "MSSQL",
      "DefaultPort": 1433,
      "Probes": [
        {
          "Description": "MSSQL TDS Protocol",
          "Send": {
            "HexString": "1201003400000000000015000601001b000102001c000103001d0000ff",
            "Explanation": "TDS pre-login packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "^\\x04\\x01",
              "Indicates": "MSSQL server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Oracle",
      "DefaultPort": 1521,
      "Probes": [
        {
          "Description": "Oracle TNS Connect",
          "Send": {
            "HexString": "003a0000010000010336010c0c2020202000000800014b0000190002820000000000040400000000040400000000",
            "Explanation": "Oracle TNS connect packet"
          },
          "ExpectedResponses": [
            {
              "Pattern": "\\x00.*\\(DESCRIPTION",
              "Indicates": "Oracle database"
            }
          ]
        }
      ]
    },
    {
      "Service": "Hazelcast",
      "DefaultPort": 5701,
      "Probes": [
        {
          "Description": "Hazelcast Member Protocol",
          "Send": {
            "HexString": "484343",
            "Explanation": "Hazelcast cluster protocol"
          },
          "ExpectedResponses": [
            {
              "Pattern": "HCC",
              "Indicates": "Hazelcast member"
            }
          ]
        }
      ]
    },
    {
      "Service": "Apache ActiveMQ",
      "DefaultPort": 61616,
      "Probes": [
        {
          "Description": "ActiveMQ OpenWire",
          "Send": {
            "HexString": "0000000c0000000001000000",
            "Explanation": "OpenWire protocol handshake"
          },
          "ExpectedResponses": [
            {
              "Pattern": "ActiveMQ",
              "Indicates": "ActiveMQ broker"
            }
          ]
        }
      ]
    },
    {
      "Service": "NATS",
      "DefaultPort": 4222,
      "Probes": [
        {
          "Description": "NATS Info",
          "Send": "CONNECT {\"verbose\":false,\"pedantic\":false,\"tls_required\":false,\"name\":\"\",\"lang\":\"go\",\"version\":\"1.0.0\",\"protocol\":1}\r\nPING\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "^INFO",
              "Indicates": "NATS server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Rsyslog",
      "DefaultPort": 514,
      "Probes": [
        {
          "Description": "Syslog Message",
          "Send": "<14>Test message",
          "ExpectedResponses": [
            {
              "Pattern": ".*",
              "Indicates": "Syslog server (may not respond)"
            }
          ]
        }
      ]
    },
    {
      "Service": "Syslog-ng",
      "DefaultPort": 601,
      "Probes": [
        {
          "Description": "Syslog-ng TCP",
          "Send": "<14>Test syslog message\n",
          "ExpectedResponses": [
            {
              "Pattern": ".*",
              "Indicates": "Syslog-ng server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Logstash",
      "DefaultPort": 9600,
      "Probes": [
        {
          "Description": "Logstash API",
          "Send": "GET / HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"version\":",
              "Indicates": "Logstash API"
            }
          ]
        }
      ]
    },
    {
      "Service": "Fluentd",
      "DefaultPort": 24224,
      "Probes": [
        {
          "Description": "Forward Protocol",
          "Send": {
            "HexString": "93a474657374a474657374a474657374",
            "Explanation": "MessagePack forward protocol"
          },
          "ExpectedResponses": [
            {
              "Pattern": ".*",
              "Indicates": "Fluentd forward input"
            }
          ]
        }
      ]
    },
    {
      "Service": "Graylog",
      "DefaultPort": 9000,
      "Probes": [
        {
          "Description": "Graylog API",
          "Send": "GET /api/ HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"cluster_id\":",
              "Indicates": "Graylog server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Splunk",
      "DefaultPort": 8089,
      "Probes": [
        {
          "Description": "Splunk Management API",
          "Send": "GET /services/server/info HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "Splunk",
              "Indicates": "Splunk server"
            }
          ]
        }
      ]
    },
    {
      "Service": "Kibana",
      "DefaultPort": 5601,
      "Probes": [
        {
          "Description": "Kibana API",
          "Send": "GET /api/status HTTP/1.0\r\n\r\n",
          "ExpectedResponses": [
            {
              "Pattern": "\"name\":\"Kibana\"",
              "Indicates": "Kibana server"
            }
          ]
        }
      ]
    }
  ]
}
