local http = require "luci.http"
local util = require "luci.util"
local ltn12 = require "luci.ltn12"
local cjson = require "cjson"
local sys   = require("luci.sys")
--local ap    = require("ap")

function table2json(t)  
        local function serialize(tbl)  
                local tmp = {}  
                for k, v in pairs(tbl) do  
                        local k_type = type(k)  
                        local v_type = type(v)  
                        local key = (k_type == "string" and "\"" .. k .. "\":")  
                            or (k_type == "number" and "")  
                        local value = (v_type == "table" and serialize(v))  
                            or (v_type == "boolean" and tostring(v))  
                            or (v_type == "string" and "\"" .. v .. "\"")  
                            or (v_type == "number" and v)  
                        tmp[#tmp + 1] = key and value and tostring(key) .. tostring(value) or nil  
                end  
                if table.maxn(tbl) == 0 then  
                        return "{" .. table.concat(tmp, ",") .. "}"  
                else  
                        return "[" .. table.concat(tmp, ",") .. "]"  
                end  
        end  
        assert(type(t) == "table")  
        return serialize(t)  
end  

function disassociate(mac)
	local cmd_disassociate = "hostapd_cli -i wlan0 disassociate "..mac
	local result = sys.exec(cmd_disassociate)
	return cjson.encode({errcode=result})
end

function add_mac_to_blacklist(mac)
    local file_path = "/var/run/hostapd_fitnew_maclist.conf"
    local file = io.open(file_path,"a")
    io.output(file)
    io.write(mac.."\n")
    io.close(file)
end

function remove_mac_from_blacklist(mac)
    local file_maclist = "/var/run/hostapd_fitnew_maclist.conf"
    local cmd_remove_mac_from_black_list_prefix = "sed -i '/%s/d' %s"
    local cmd_remove_mac_from_black_list = string.format(cmd_remove_mac_from_black_list_prefix,mac,file_maclist)
    syslog(cmd_remove_mac_from_black_list)
    local result = sys.call(cmd_remove_mac_from_black_list)
    return cjson.encode({errcode=result})
end

function syslog(log)
	os.execute(string.format('logger "%s"',log))
end

function os.capture(cmd)
	local s = sys.exec(cmd)
	return s
end

cmd_redirect = "ebtables -t nat -I PREROUTING -s %s -p ipv4 --ip-proto udp --ip-dst 239.255.255.250 --ip-dport 1900 -j dnat --to-destination %s"
cmd_accept   = "ebtables -I FORWARD -s %s -d %s -p ipv4 --ip-proto udp --ip-dport 1900 -j ACCEPT"
cmd_prefix = "cat /tmp/dhcp.leases | grep %s | awk '{print $2}'"

cmd_rm_redirect = "ebtables -t nat -D PREROUTING -s %s -p ipv4 --ip-proto udp --ip-dst 239.255.255.250 --ip-dport 1900 -j dnat --to-destination %s"
cmd_rm_accept   = "ebtables -D FORWARD -s %s -d %s -p ipv4 --ip-proto udp --ip-dport 1900 -j ACCEPT"

function get_mac_by_ip(ip)
	local cmd_get_mac_by_ip = string.format(cmd_prefix,ip)
	local mac = sys.exec(cmd_get_mac_by_ip)
  return string.gsub(mac,"\n","")
end

function build_rule(mac_client,mac_server)
	local cmd_redirect_client2server = string.format(cmd_redirect,mac_client,mac_server)
	local cmd_redirect_server2client = string.format(cmd_redirect,mac_server,mac_client)
	local cmd_accept_client2server   = string.format(cmd_accept,mac_client,mac_server)
	local cmd_accept_server2client   = string.format(cmd_accept,mac_server,mac_client)

	local table_cmd = {cmd_redirect_client2server,cmd_redirect_server2client,cmd_accept_client2server,cmd_accept_server2client}
	for i=1,4 do
		local result = sys.call(table_cmd[i])
		if(result ~= 0) then
			return cjson.encode({errcode=1,cmd=table_cmd[i]})
		end
	end
  return 0
end

function rm_rule(mac_client,mac_server)
	local cmd_rm_redirect_client2server = string.format(cmd_rm_redirect,mac_client,mac_server)
	local cmd_rm_redirect_server2client = string.format(cmd_rm_redirect,mac_server,mac_client)
	local cmd_rm_accept_client2server   = string.format(cmd_rm_accept,mac_client,mac_server)
	local cmd_rm_accept_server2client   = string.format(cmd_rm_accept,mac_server,mac_client)
  
	local table_cmd = {cmd_rm_redirect_client2server,cmd_rm_redirect_server2client,cmd_rm_accept_client2server,cmd_rm_accept_server2client}
	for i=1,4 do
		local result = sys.call(table_cmd[i])
		if(result ~= 0) then
			syslog("call error: "..table_cmd[i])
		end
	end
end

function record_userid_servermac_to_file(userid,server_mac)
  local record_userid_servermac_file = "/var/run/fitnew_userid_mac"
  local line = string.format("%s;;%s",userid,server_mac)
  local file = io.open(record_userid_servermac_file,"a")
  io.output(file)
  io.write(line.."\n")
  io.close(file)
end

function delete_userid_entry(userid)
  local record_userid_servermac_file = "/var/run/fitnew_userid_mac"
  local cmd_delete_userid_entry_prefix = "sed -i '/^%s/d' %s"
  local cmd_delete_userid_entry = string.format(cmd_delete_userid_entry_prefix,userid,record_userid_servermac_file)
  local result = sys.exec(cmd_delete_userid_entry)
  return  cjson.encode({errcode=result})
end



function get_server_mac_from_record_file(userid)
  local record_userid_server_mac_file = "/var/run/fitnew_userid_mac"
  local cmd_get_server_mac_by_user_id_prefix = [[cat /var/run/fitnew_userid_mac | grep %s | awk -F";" '{print $3}']]  
  local cmd_get_server_mac_by_user_id = string.format(cmd_get_server_mac_by_user_id_prefix,userid)
  local server_mac = sys.exec(cmd_get_server_mac_by_user_id)
  return string.gsub(server_mac,"\n","")
end

function update_record_file(userid,mac_client,mac_server)
  local record_userid_server_mac_file = "/var/run/fitnew_userid_mac"
  local record_new = string.format("%s;%s;%s",userid,mac_client,mac_server)
  local cmd_replace_record_prefix = "sed -i 's/^%s/%s/'"
  local cmd_replace_record = string.format(cmd_replace_record_prefix,userid,record_new)
  local result = sys.exec(cmd_replace_record)
  return result
end

function parse_data_from_phone(data,env)
  local ip_client = env.REMOTE_HOST
	local mac_client = get_mac_by_ip(ip_client)
  local userid    = data.userid
  local mac_server = get_server_mac_from_record_file(userid)
  local result = build_rule(data.client,mac_server)  -- 实际为mac_client,为了方便测试，改为data.client
  update_record_file(userid,mac_client,mac_server)
  if(result == 0) then
    return cjson.encode({userid=userid,client=mac_client})
  else
    return result
  end
end

function parse_data_from_pad(data,env)
	local ip_client = env.REMOTE_HOST
	local mac_client = get_mac_by_ip(ip_client)
	local mac_server = data.server
  local userid    = data.userid
	if(data.action == 0) then --用户扫二维码时，平板发出消息(消息中有client地址则从黑名单中移除,主要是为了将用户ID和平板mac地址记录下来)
        local result
        if(data.client ~= nil) then
          result = remove_mac_from_blacklist(data.client)
        end
        record_userid_servermac_to_file(userid,data.server)
        return result
  	elseif (data.action == 1) then --消息从平板发出，请求路由器将设备踢下线并将mac地址拉入黑名单
        local result_dis = disassociate(data.client) --踢掉用户
    		local result_rm_rule = rm_rule(data.client,mac_server) --删除规则(本应是mac_client,为了方便测试改为data.client)
        local result_add_mac_to_blacklist = add_mac_to_blacklist(data.client) --将用户加入黑名单
        local result_delete_userid_entry  = delete_userid_entry(userid)
        return result_dis
    elseif (data.action == 2) then --平板向路由器请求获取wifi的SSID及密码
        local cmd_get_wifi_ssid = "uci get wireless.default_radio0.ssid"
        local cmd_get_wifi_key = "uci get wireless.default_radio0.key"
        
        local result_ssid = sys.exec(cmd_get_wifi_ssid)
        local result_key  = sys.exec(cmd_get_wifi_key)
        local result  = {ssid= string.gsub(result_ssid,"\n",""),key= string.gsub(result_key,"\n","")}
        return cjson.encode(result)
  	end
end

function handle_request(env)
	uhttpd.send("Status: 200 OK\r\n")
	uhttpd.send("Content-Type: text/html\r\n\r\n")
 
	local client_data = io.read("*all")
	local data = cjson.decode(client_data)
	if(data.type == 0) then
		local result = parse_data_from_pad(data,env)
    syslog(result)
    uhttpd.send(result)
  elseif(data.type == 1) then
    local result = parse_data_from_phone(data,env)
    uhttpd.send(result)
  end
end

