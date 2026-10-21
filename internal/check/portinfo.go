package check

import "github.com/z6il/perimeter/internal/store"

var portNames = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3",
	111: "RPC", 135: "MS RPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
	465: "SMTPS", 514: "Syslog", 587: "SMTP submission", 631: "IPP", 636: "LDAPS", 873: "rsync",
	993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "SQL Server", 1521: "Oracle",
	1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2082: "cPanel", 2083: "cPanel", 2086: "WHM", 2087: "WHM",
	2181: "ZooKeeper", 2222: "SSH (alt)", 2375: "Docker API", 2376: "Docker API (TLS)", 2379: "etcd",
	3000: "dev server", 3128: "proxy", 3306: "MySQL", 3389: "RDP", 4369: "Erlang EPMD", 4848: "GlassFish admin",
	5000: "dev server", 5060: "SIP", 5432: "PostgreSQL", 5601: "Kibana", 5672: "RabbitMQ", 5900: "VNC",
	5984: "CouchDB", 5985: "WinRM", 5986: "WinRM (TLS)", 6000: "X11", 6379: "Redis", 6443: "Kubernetes API",
	6667: "IRC", 7001: "WebLogic", 7474: "Neo4j", 7687: "Neo4j Bolt", 8080: "HTTP (alt)", 8086: "InfluxDB",
	8088: "HTTP (alt)", 8089: "Splunk", 8161: "ActiveMQ", 8200: "Vault", 8443: "HTTPS (alt)", 8500: "Consul",
	8834: "Nessus", 8888: "HTTP (alt)", 9000: "admin UI", 9042: "Cassandra", 9090: "Prometheus",
	9092: "Kafka", 9100: "node exporter", 9200: "Elasticsearch", 9300: "Elasticsearch", 9418: "Git",
	9443: "HTTPS (alt)", 10000: "Webmin", 10250: "Kubelet", 11211: "Memcached", 15672: "RabbitMQ admin",
	25565: "Minecraft", 27017: "MongoDB", 28017: "MongoDB HTTP", 32400: "Plex", 50000: "Jenkins agent",
}

// PortLabel names the service usually found on a port, or "".
func PortLabel(port int) string { return portNames[port] }

// Ports whose exposure usually means data or full control is up for grabs.
var criticalPorts = map[int]bool{
	23: true, 2375: true, 2379: true, 4369: true, 5900: true, 5984: true, 6379: true, 9042: true,
	9200: true, 9300: true, 10250: true, 11211: true, 27017: true, 28017: true,
}

var highPorts = map[int]bool{
	21: true, 135: true, 139: true, 445: true, 1433: true, 1521: true, 2049: true, 3306: true, 3389: true,
	5432: true, 5601: true, 5985: true, 5986: true, 6443: true, 7474: true, 7687: true, 8086: true,
	8089: true, 8161: true, 8200: true, 8500: true, 9090: true, 9092: true, 9100: true, 10000: true, 15672: true,
}

// PortSeverity grades an unexpected open port.
func PortSeverity(port int) store.Severity {
	switch {
	case criticalPorts[port]:
		return store.Critical
	case highPorts[port]:
		return store.High
	}
	return store.Medium
}
