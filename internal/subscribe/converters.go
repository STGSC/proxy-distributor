package subscribe

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"proxy-distributor/internal/models"
)

// 节点转换函数

// convertNodeToSurge 转换节点为Surge格式
func (e *Exporter) convertNodeToSurge(node *models.Node, watermark bool, userID string) string {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	switch node.Protocol {
	case "ss":
		return fmt.Sprintf("%s = ss, %s, %d, encrypt-method=%s, password=%s",
			name, node.Host, node.Port, node.Params["cipher"], node.Params["password"])
	case "vmess":
		config := fmt.Sprintf("%s = vmess, %s, %d, username=%s",
			name, node.Host, node.Port, node.Params["uuid"])
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			config += ", tls=true"
		}
		return config
	case "trojan":
		return fmt.Sprintf("%s = trojan, %s, %d, password=%s",
			name, node.Host, node.Port, node.Params["password"])
	default:
		return ""
	}
}

// convertNodeToV2Ray 转换节点为V2Ray格式
func (e *Exporter) convertNodeToV2Ray(node *models.Node, watermark bool, userID string) map[string]interface{} {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	outbound := map[string]interface{}{
		"tag":      name,
		"protocol": node.Protocol,
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": node.Host,
					"port":    node.Port,
					"users": []map[string]interface{}{
						{
							"id": node.Params["uuid"],
						},
					},
				},
			},
		},
	}

	if node.Protocol == "vmess" {
		outbound["streamSettings"] = map[string]interface{}{
			"network": "tcp",
		}
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			outbound["streamSettings"].(map[string]interface{})["security"] = "tls"
		}
	}

	return outbound
}

// convertNodeToTrojanURI 转换节点为Trojan URI
func (e *Exporter) convertNodeToTrojanURI(node *models.Node, watermark bool, userID string) string {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	password := node.Params["password"]
	encodedName := url.QueryEscape(name)

	return fmt.Sprintf("trojan://%s@%s:%d#%s", password, node.Host, node.Port, encodedName)
}

// convertNodeToSSRURI 转换节点为SSR URI
func (e *Exporter) convertNodeToSSRURI(node *models.Node, watermark bool, userID string) string {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	// SSR URI格式: ssr://base64(host:port:protocol:method:obfs:password_base64/?obfsparam=&protoparam=&remarks=&group=)
	password := base64.StdEncoding.EncodeToString([]byte(node.Params["password"]))
	remarks := base64.StdEncoding.EncodeToString([]byte(name))

	ssrString := fmt.Sprintf("%s:%d:%s:%s:%s:%s/?obfsparam=&protoparam=&remarks=%s&group=",
		node.Host, node.Port, "origin", node.Params["cipher"], "plain", password, remarks)

	return "ssr://" + base64.StdEncoding.EncodeToString([]byte(ssrString))
}

// convertNodeToSurfboard 转换节点为Surfboard格式
func (e *Exporter) convertNodeToSurfboard(node *models.Node, watermark bool, userID string) string {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	switch node.Protocol {
	case "ss":
		return fmt.Sprintf("%s = ss, %s, %d, encrypt-method=%s, password=%s",
			name, node.Host, node.Port, node.Params["cipher"], node.Params["password"])
	case "vmess":
		config := fmt.Sprintf("%s = vmess, %s, %d, username=%s",
			name, node.Host, node.Port, node.Params["uuid"])
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			config += ", tls=true"
		}
		return config
	case "trojan":
		return fmt.Sprintf("%s = trojan, %s, %d, password=%s",
			name, node.Host, node.Port, node.Params["password"])
	default:
		return ""
	}
}

// convertNodeToQuantumult 转换节点为Quantumult格式
func (e *Exporter) convertNodeToQuantumult(node *models.Node, watermark bool, userID string) string {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	switch node.Protocol {
	case "ss":
		return fmt.Sprintf("shadowsocks=%s:%d, method=%s, password=%s, fast-open=false, udp-relay=false, tag=%s",
			node.Host, node.Port, node.Params["cipher"], node.Params["password"], name)
	case "vmess":
		config := fmt.Sprintf("vmess=%s:%d, method=auto, password=%s, fast-open=false, udp-relay=false, tag=%s",
			node.Host, node.Port, node.Params["uuid"], name)
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			config += ", obfs=over-tls"
		}
		return config
	case "trojan":
		return fmt.Sprintf("trojan=%s:%d, password=%s, fast-open=false, udp-relay=false, tag=%s",
			node.Host, node.Port, node.Params["password"], name)
	default:
		return ""
	}
}

// convertNodeToQuantumultX 转换节点为Quantumult X格式
func (e *Exporter) convertNodeToQuantumultX(node *models.Node, watermark bool, userID string) string {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	switch node.Protocol {
	case "ss":
		return fmt.Sprintf("shadowsocks=%s:%d, method=%s, password=%s, fast-open=false, udp-relay=false, tag=%s",
			node.Host, node.Port, node.Params["cipher"], node.Params["password"], name)
	case "vmess":
		config := fmt.Sprintf("vmess=%s:%d, method=auto, password=%s, fast-open=false, udp-relay=false, tag=%s",
			node.Host, node.Port, node.Params["uuid"], name)
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			config += ", obfs=over-tls"
		}
		return config
	case "trojan":
		return fmt.Sprintf("trojan=%s:%d, password=%s, fast-open=false, udp-relay=false, tag=%s",
			node.Host, node.Port, node.Params["password"], name)
	default:
		return ""
	}
}

// convertNodeToLoon 转换节点为Loon格式
func (e *Exporter) convertNodeToLoon(node *models.Node, watermark bool, userID string) string {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	switch node.Protocol {
	case "ss":
		return fmt.Sprintf("%s = Shadowsocks, %s, %d, %s, %s",
			name, node.Host, node.Port, node.Params["cipher"], node.Params["password"])
	case "vmess":
		config := fmt.Sprintf("%s = VMess, %s, %d, %s",
			name, node.Host, node.Port, node.Params["uuid"])
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			config += ", tls=true"
		}
		return config
	case "trojan":
		return fmt.Sprintf("%s = Trojan, %s, %d, %s",
			name, node.Host, node.Port, node.Params["password"])
	default:
		return ""
	}
}

// convertNodeToMellow 转换节点为Mellow格式
func (e *Exporter) convertNodeToMellow(node *models.Node, watermark bool, userID string) map[string]interface{} {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	outbound := map[string]interface{}{
		"tag":      name,
		"protocol": node.Protocol,
		"settings": map[string]interface{}{
			"address": node.Host,
			"port":    node.Port,
		},
	}

	switch node.Protocol {
	case "ss":
		outbound["settings"].(map[string]interface{})["method"] = node.Params["cipher"]
		outbound["settings"].(map[string]interface{})["password"] = node.Params["password"]
	case "vmess":
		outbound["settings"].(map[string]interface{})["vnext"] = []map[string]interface{}{
			{
				"address": node.Host,
				"port":    node.Port,
				"users": []map[string]interface{}{
					{
						"id": node.Params["uuid"],
					},
				},
			},
		}
	case "trojan":
		outbound["settings"].(map[string]interface{})["password"] = node.Params["password"]
	}

	return outbound
}

// convertNodeToSIP002 转换节点为SIP002格式
func (e *Exporter) convertNodeToSIP002(node *models.Node, watermark bool, userID string) string {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	password := node.Params["password"]
	encodedName := url.QueryEscape(name)

	return fmt.Sprintf("ss://%s@%s:%d#%s",
		base64.StdEncoding.EncodeToString([]byte(node.Params["cipher"]+":"+password)),
		node.Host, node.Port, encodedName)
}

// convertNodeToShadowsocksD 转换节点为ShadowsocksD格式
func (e *Exporter) convertNodeToShadowsocksD(node *models.Node, watermark bool, userID string) string {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	password := node.Params["password"]
	encodedName := url.QueryEscape(name)

	return fmt.Sprintf("ss://%s@%s:%d#%s",
		base64.StdEncoding.EncodeToString([]byte(node.Params["cipher"]+":"+password)),
		node.Host, node.Port, encodedName)
}
