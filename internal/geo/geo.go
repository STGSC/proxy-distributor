package geo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GeoLocation 地理位置信息
type GeoLocation struct {
	Country string `json:"country"`
	City    string `json:"city"`
}

// GeoResolver 地理位置解析器
type GeoResolver struct {
	client *http.Client
}

// NewGeoResolver 创建地理位置解析器
func NewGeoResolver() *GeoResolver {
	return &GeoResolver{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ResolveLocation 解析节点地理位置
func (gr *GeoResolver) ResolveLocation(nodeName string) (*GeoLocation, error) {
	// 首先尝试从节点名称中提取国家信息
	if location := gr.extractLocationFromName(nodeName); location != nil {
		return location, nil
	}

	// 如果无法从名称提取，返回默认值
	return &GeoLocation{
		Country: "Unknown",
		City:    "Unknown",
	}, nil
}

// extractLocationFromName 从节点名称中提取地理位置信息
func (gr *GeoResolver) extractLocationFromName(nodeName string) *GeoLocation {
	// 国家代码映射（常用国家）
	countryMap := map[string]string{
		"🇺🇸": "United States", "🇨🇳": "China", "🇯🇵": "Japan", "🇰🇷": "South Korea",
		"🇸🇬": "Singapore", "🇭🇰": "Hong Kong", "🇹🇼": "Taiwan", "🇬🇧": "United Kingdom",
		"🇩🇪": "Germany", "🇫🇷": "France", "🇮🇹": "Italy", "🇪🇸": "Spain",
		"🇳🇱": "Netherlands", "🇨🇦": "Canada", "🇦🇺": "Australia", "🇳🇿": "New Zealand",
		"🇧🇷": "Brazil", "🇮🇳": "India", "🇷🇺": "Russia", "🇹🇷": "Turkey",
		"🇦🇪": "United Arab Emirates", "🇸🇦": "Saudi Arabia", "🇮🇱": "Israel",
		"🇵🇱": "Poland", "🇨🇿": "Czech Republic", "🇦🇹": "Austria", "🇨🇭": "Switzerland",
		"🇸🇪": "Sweden", "🇳🇴": "Norway", "🇩🇰": "Denmark", "🇫🇮": "Finland",
		"🇧🇪": "Belgium", "🇱🇺": "Luxembourg", "🇮🇪": "Ireland", "🇵🇹": "Portugal",
		"🇬🇷": "Greece", "🇭🇺": "Hungary", "🇷🇴": "Romania", "🇧🇬": "Bulgaria",
		"🇭🇷": "Croatia", "🇸🇮": "Slovenia", "🇸🇰": "Slovakia", "🇱🇹": "Lithuania",
		"🇱🇻": "Latvia", "🇪🇪": "Estonia", "🇲🇽": "Mexico", "🇦🇷": "Argentina",
		"🇨🇱": "Chile", "🇨🇴": "Colombia", "🇵🇪": "Peru", "🇻🇪": "Venezuela",
		"🇿🇦": "South Africa", "🇪🇬": "Egypt", "🇳🇬": "Nigeria", "🇰🇪": "Kenya",
		"🇲🇦": "Morocco", "🇹🇳": "Tunisia", "🇩🇿": "Algeria", "🇱🇾": "Libya",
		"🇮🇷": "Iran", "🇮🇶": "Iraq", "🇸🇾": "Syria", "🇱🇧": "Lebanon",
		"🇯🇴": "Jordan", "🇰🇼": "Kuwait", "🇶🇦": "Qatar", "🇧🇭": "Bahrain",
		"🇴🇲": "Oman", "🇾🇪": "Yemen", "🇦🇫": "Afghanistan", "🇵🇰": "Pakistan",
		"🇧🇩": "Bangladesh", "🇱🇰": "Sri Lanka", "🇲🇻": "Maldives", "🇳🇵": "Nepal",
		"🇧🇹": "Bhutan", "🇲🇲": "Myanmar", "🇹🇭": "Thailand", "🇱🇦": "Laos",
		"🇰🇭": "Cambodia", "🇻🇳": "Vietnam", "🇵🇭": "Philippines", "🇮🇩": "Indonesia",
		"🇲🇾": "Malaysia", "🇧🇳": "Brunei", "🇹🇱": "East Timor", "🇵🇬": "Papua New Guinea",
		"🇫🇯": "Fiji", "🇳🇨": "New Caledonia", "🇻🇺": "Vanuatu", "🇸🇧": "Solomon Islands",
		"🇰🇮": "Kiribati", "🇹🇻": "Tuvalu", "🇳🇷": "Nauru", "🇵🇼": "Palau",
		"🇫🇲": "Micronesia", "🇲🇭": "Marshall Islands", "🇼🇸": "Samoa", "🇹🇴": "Tonga",
		"🇨🇰": "Cook Islands", "🇳🇺": "Niue", "🇹🇰": "Tokelau", "🇵🇫": "French Polynesia",
		"🇳🇫": "Norfolk Island", "🇨🇨": "Cocos Islands", "🇨🇽": "Christmas Island",
		"🇦🇸": "American Samoa", "🇬🇺": "Guam", "🇲🇵": "Northern Mariana Islands",
		"🇻🇮": "U.S. Virgin Islands", "🇵🇷": "Puerto Rico", "🇧🇸": "Bahamas",
		"🇧🇧": "Barbados", "🇧🇿": "Belize", "🇨🇷": "Costa Rica", "🇨🇺": "Cuba",
		"🇩🇲": "Dominica", "🇩🇴": "Dominican Republic", "🇬🇩": "Grenada",
		"🇬🇹": "Guatemala", "🇭🇹": "Haiti", "🇭🇳": "Honduras", "🇯🇲": "Jamaica",
		"🇰🇳": "Saint Kitts and Nevis", "🇱🇨": "Saint Lucia", "🇻🇨": "Saint Vincent and the Grenadines",
		"🇸🇷": "Suriname", "🇹🇹": "Trinidad and Tobago", "🇺🇾": "Uruguay",
		"🇧🇴": "Bolivia", "🇪🇨": "Ecuador", "🇬🇾": "Guyana", "🇵🇾": "Paraguay",
		"🇬🇫": "French Guiana", "🇫🇰": "Falkland Islands", "🇬🇸": "South Georgia and the South Sandwich Islands",
		"🇸🇻": "El Salvador", "🇳🇮": "Nicaragua", "🇵🇦": "Panama", "🇦🇬": "Antigua and Barbuda",
		"🇦🇮": "Anguilla", "🇦🇼": "Aruba", "🇧🇲": "Bermuda", "🇧🇶": "Bonaire, Sint Eustatius and Saba",
		"🇨🇼": "Curaçao", "🇬🇱": "Greenland", "🇬🇵": "Guadeloupe", "🇯🇪": "Jersey",
		"🇲🇶": "Martinique", "🇲🇸": "Montserrat", "🇵🇳": "Pitcairn Islands",
		"🇸🇭": "Saint Helena, Ascension and Tristan da Cunha", "🇵🇲": "Saint Pierre and Miquelon",
		"🇸🇽": "Sint Maarten", "🇹🇨": "Turks and Caicos Islands", "🇻🇬": "British Virgin Islands",
		"🇼🇫": "Wallis and Futuna", "🇦🇩": "Andorra", "🇦🇱": "Albania", "🇦🇲": "Armenia",
		"🇦🇿": "Azerbaijan", "🇧🇦": "Bosnia and Herzegovina", "🇧🇾": "Belarus", "🇨🇾": "Cyprus",
		"🇬🇪": "Georgia", "🇮🇸": "Iceland", "🇽🇰": "Kosovo", "🇱🇮": "Liechtenstein",
		"🇲🇰": "North Macedonia", "🇲🇩": "Moldova", "🇲🇨": "Monaco", "🇲🇪": "Montenegro",
		"🇲🇹": "Malta", "🇷🇸": "Serbia", "🇸🇲": "San Marino", "🇺🇦": "Ukraine", "🇻🇦": "Vatican City",
		"🇰🇿": "Kazakhstan", "🇰🇬": "Kyrgyzstan", "🇹🇯": "Tajikistan", "🇹🇲": "Turkmenistan",
		"🇺🇿": "Uzbekistan",
	}

	// 查找节点名称中的国家标志
	for flag, country := range countryMap {
		if strings.Contains(nodeName, flag) {
			return &GeoLocation{
				Country: country,
				City:    "Unknown", // 城市信息通常不在节点名称中
			}
		}
	}

	// 如果没有找到标志，尝试查找国家名称关键词
	countryKeywords := map[string]string{
		"美国": "United States", "中国": "China", "日本": "Japan", "韩国": "South Korea",
		"新加坡": "Singapore", "香港": "Hong Kong", "台湾": "Taiwan", "英国": "United Kingdom",
		"德国": "Germany", "法国": "France", "意大利": "Italy", "西班牙": "Spain",
		"荷兰": "Netherlands", "加拿大": "Canada", "澳大利亚": "Australia", "新西兰": "New Zealand",
		"巴西": "Brazil", "印度": "India", "俄罗斯": "Russia", "土耳其": "Turkey",
		"阿联酋": "United Arab Emirates", "沙特": "Saudi Arabia", "以色列": "Israel",
		"波兰": "Poland", "捷克": "Czech Republic", "奥地利": "Austria", "瑞士": "Switzerland",
		"瑞典": "Sweden", "挪威": "Norway", "丹麦": "Denmark", "芬兰": "Finland",
		"比利时": "Belgium", "卢森堡": "Luxembourg", "爱尔兰": "Ireland", "葡萄牙": "Portugal",
		"希腊": "Greece", "匈牙利": "Hungary", "罗马尼亚": "Romania", "保加利亚": "Bulgaria",
		"克罗地亚": "Croatia", "斯洛文尼亚": "Slovenia", "斯洛伐克": "Slovakia", "立陶宛": "Lithuania",
		"拉脱维亚": "Latvia", "爱沙尼亚": "Estonia", "墨西哥": "Mexico", "阿根廷": "Argentina",
		"智利": "Chile", "哥伦比亚": "Colombia", "秘鲁": "Peru", "委内瑞拉": "Venezuela",
		"南非": "South Africa", "埃及": "Egypt", "尼日利亚": "Nigeria", "肯尼亚": "Kenya",
		"摩洛哥": "Morocco", "突尼斯": "Tunisia", "阿尔及利亚": "Algeria", "利比亚": "Libya",
		"伊朗": "Iran", "伊拉克": "Iraq", "叙利亚": "Syria", "黎巴嫩": "Lebanon",
		"约旦": "Jordan", "科威特": "Kuwait", "卡塔尔": "Qatar", "巴林": "Bahrain",
		"阿曼": "Oman", "也门": "Yemen", "阿富汗": "Afghanistan", "巴基斯坦": "Pakistan",
		"孟加拉": "Bangladesh", "斯里兰卡": "Sri Lanka", "马尔代夫": "Maldives", "尼泊尔": "Nepal",
		"不丹": "Bhutan", "缅甸": "Myanmar", "泰国": "Thailand", "老挝": "Laos",
		"柬埔寨": "Cambodia", "越南": "Vietnam", "菲律宾": "Philippines", "印度尼西亚": "Indonesia",
		"马来西亚": "Malaysia", "文莱": "Brunei", "东帝汶": "East Timor", "巴布亚新几内亚": "Papua New Guinea",
		"斐济": "Fiji", "新喀里多尼亚": "New Caledonia", "瓦努阿图": "Vanuatu", "所罗门群岛": "Solomon Islands",
		"基里巴斯": "Kiribati", "图瓦卢": "Tuvalu", "瑙鲁": "Nauru", "帕劳": "Palau",
		"密克罗尼西亚": "Micronesia", "马绍尔群岛": "Marshall Islands", "萨摩亚": "Samoa", "汤加": "Tonga",
		"库克群岛": "Cook Islands", "纽埃": "Niue", "托克劳": "Tokelau", "法属波利尼西亚": "French Polynesia",
		"诺福克岛": "Norfolk Island", "科科斯群岛": "Cocos Islands", "圣诞岛": "Christmas Island",
		"美属萨摩亚": "American Samoa", "关岛": "Guam", "北马里亚纳群岛": "Northern Mariana Islands",
		"美属维尔京群岛": "U.S. Virgin Islands", "波多黎各": "Puerto Rico", "巴哈马": "Bahamas",
		"巴巴多斯": "Barbados", "伯利兹": "Belize", "哥斯达黎加": "Costa Rica", "古巴": "Cuba",
		"多米尼克": "Dominica", "多米尼加": "Dominican Republic", "格林纳达": "Grenada",
		"危地马拉": "Guatemala", "海地": "Haiti", "洪都拉斯": "Honduras", "牙买加": "Jamaica",
		"圣基茨和尼维斯": "Saint Kitts and Nevis", "圣卢西亚": "Saint Lucia", "圣文森特和格林纳丁斯": "Saint Vincent and the Grenadines",
		"苏里南": "Suriname", "特立尼达和多巴哥": "Trinidad and Tobago", "乌拉圭": "Uruguay",
		"玻利维亚": "Bolivia", "厄瓜多尔": "Ecuador", "圭亚那": "Guyana", "巴拉圭": "Paraguay",
		"法属圭亚那": "French Guiana", "福克兰群岛": "Falkland Islands", "南乔治亚和南桑威奇群岛": "South Georgia and the South Sandwich Islands",
		"萨尔瓦多": "El Salvador", "尼加拉瓜": "Nicaragua", "巴拿马": "Panama", "安提瓜和巴布达": "Antigua and Barbuda",
		"安圭拉": "Anguilla", "阿鲁巴": "Aruba", "百慕大": "Bermuda", "博奈尔、圣尤斯特歇斯和萨巴": "Bonaire, Sint Eustatius and Saba",
		"库拉索": "Curaçao", "格陵兰": "Greenland", "瓜德罗普": "Guadeloupe", "泽西": "Jersey",
		"马提尼克": "Martinique", "蒙特塞拉特": "Montserrat", "皮特凯恩群岛": "Pitcairn Islands",
		"圣赫勒拿、阿森松和特里斯坦-达库尼亚": "Saint Helena, Ascension and Tristan da Cunha",
		"圣皮埃尔和密克隆":           "Saint Pierre and Miquelon", "圣马丁": "Sint Maarten", "特克斯和凯科斯群岛": "Turks and Caicos Islands",
		"英属维尔京群岛": "British Virgin Islands", "瓦利斯和富图纳": "Wallis and Futuna", "安道尔": "Andorra",
		"阿尔巴尼亚": "Albania", "亚美尼亚": "Armenia", "阿塞拜疆": "Azerbaijan", "波斯尼亚和黑塞哥维那": "Bosnia and Herzegovina",
		"白俄罗斯": "Belarus", "塞浦路斯": "Cyprus", "格鲁吉亚": "Georgia", "冰岛": "Iceland",
		"科索沃": "Kosovo", "列支敦士登": "Liechtenstein", "北马其顿": "North Macedonia", "摩尔多瓦": "Moldova",
		"摩纳哥": "Monaco", "黑山": "Montenegro", "马耳他": "Malta", "塞尔维亚": "Serbia",
		"圣马力诺": "San Marino", "乌克兰": "Ukraine", "梵蒂冈": "Vatican City",
		"哈萨克斯坦": "Kazakhstan", "吉尔吉斯斯坦": "Kyrgyzstan", "塔吉克斯坦": "Tajikistan",
		"土库曼斯坦": "Turkmenistan", "乌兹别克斯坦": "Uzbekistan",
	}

	// 查找节点名称中的国家关键词
	for keyword, country := range countryKeywords {
		if strings.Contains(nodeName, keyword) {
			return &GeoLocation{
				Country: country,
				City:    "Unknown",
			}
		}
	}

	return nil
}

// resolveLocationViaProxy 通过代理连接测试出口IP位置
func (gr *GeoResolver) resolveLocationViaProxy(proxyHost string) (*GeoLocation, error) {
	// 创建通过代理的HTTP客户端
	proxyClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{
				Scheme: "http",
				Host:   proxyHost,
			}),
		},
	}

	// 通过代理访问IP检测服务
	resp, err := proxyClient.Get("http://ip-api.com/json?fields=country,city")
	if err != nil {
		// 如果代理连接失败，回退到直接IP解析
		return gr.resolveLocationDirect(proxyHost)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return gr.resolveLocationDirect(proxyHost)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return gr.resolveLocationDirect(proxyHost)
	}

	var location GeoLocation
	if err := json.Unmarshal(body, &location); err != nil {
		return gr.resolveLocationDirect(proxyHost)
	}

	return &location, nil
}

// resolveLocationDirect 直接解析IP地址的地理位置（备用方法）
func (gr *GeoResolver) resolveLocationDirect(ip string) (*GeoLocation, error) {
	// 使用免费的IP地理位置API
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=country,city", ip)

	resp, err := gr.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求地理位置API失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("地理位置API返回错误状态: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取API响应失败: %w", err)
	}

	var location GeoLocation
	if err := json.Unmarshal(body, &location); err != nil {
		return nil, fmt.Errorf("解析地理位置数据失败: %w", err)
	}

	return &location, nil
}

// ResolveLocationBatch 批量解析IP地址的地理位置
func (gr *GeoResolver) ResolveLocationBatch(ips []string) (map[string]*GeoLocation, error) {
	results := make(map[string]*GeoLocation)

	// 为了避免API限制，我们限制并发请求数量
	semaphore := make(chan struct{}, 5) // 最多5个并发请求

	for _, ip := range ips {
		semaphore <- struct{}{} // 获取信号量
		go func(ip string) {
			defer func() { <-semaphore }() // 释放信号量

			location, err := gr.ResolveLocation(ip)
			if err != nil {
				// 如果解析失败，设置默认值
				results[ip] = &GeoLocation{
					Country: "Unknown",
					City:    "Unknown",
				}
			} else {
				results[ip] = location
			}
		}(ip)
	}

	// 等待所有请求完成
	for i := 0; i < cap(semaphore); i++ {
		semaphore <- struct{}{}
	}

	return results, nil
}
