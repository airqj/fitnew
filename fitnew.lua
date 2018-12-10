local http = require "luci.http"
local util = require "luci.util"
local ltn12 = require "luci.ltn12"
local cjson = require "cjson"
local sys   = require("luci.sys")
local http=require("socket.http")
--local ap    = require("ap")








function syslog(log)
	os.execute(string.format([[logger "%s"]],log))
end

function os.capture(cmd)
	local s = sys.exec(cmd)
	return s
end

function request_server(server,client,token)
   syslog("server="..server)
   syslog("client="..client)
   syslog("token="..token)
   local request_body_prefix = [[
		<?xml version="1.0" encoding="utf-8"?>
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">  
      <s:Body> 
        <u:SetDeviceAuthorization xmlns:u="urn:schemas-upnp-org:service:ConnectionManager:1">  
          <DeviceIP>%s</DeviceIP>  
          <Token>%s</Token>  
          <Enable>1</Enable> 
        </u:SetDeviceAuthorization> 
      </s:Body> 
    </s:Envelope>
    ]]
  
  local request_body = string.format(request_body_prefix,client,token)
  
  --syslog(request_body)
  
  local response_body = {}

  local res, code, response_headers = http.request{
      url = server.."/_urn:schemas-upnp-org:service:ConnectionManager_control",
      method = "POST",
      headers =
        {
            ["SOAPACTION"] = [["urn:schemas-upnp-org:service:ConnectionManager:1#SetDeviceAuthorization"]];
            ["Content-Type"] = [[text/xml]];
            ["Content-Length"] = #request_body;
        },
        source = ltn12.source.string(request_body),
        sink = ltn12.sink.table(response_body),
  }

  --syslog("response_headers.length="..response_headers.content-length)
  return code
end

function parse_data_from_phone(data,env)
  syslog("type=1")
  local ip_client = env.REMOTE_HOST
  local server = data.server
  local token  = data.token
  local result = request_server(server,ip_client,token)
  return result
end

function get_phone_mac_from_record_file_by_userid(userid)
  local cmd_get_phone_mac_by_user_id_prefix = [[cat /var/run/fitnew_userid_mac | grep %s | awk -F";" '{print $2}']]  
  local cmd_get_phone_mac_by_user_id = string.format(cmd_get_phone_mac_by_user_id_prefix,userid)
  
  local phone_mac = sys.exec(cmd_get_phone_mac_by_user_id)

  if(string.len(phone_mac) == 0 or string.len(phone_mac) == 1) then
    return 0
  else
    return string.gsub(phone_mac,"\n","")
  end
end

function get_server_mac_from_record_file_by_userid(userid)
  --local record_userid_server_mac_file = "/var/run/fitnew_userid_mac"
  local cmd_get_server_mac_by_user_id_prefix = [[cat /var/run/fitnew_userid_mac | grep %s | awk -F";" '{print $3}']]  
  local cmd_get_server_mac_by_user_id = string.format(cmd_get_server_mac_by_user_id_prefix,userid)
  local server_mac = sys.exec(cmd_get_server_mac_by_user_id)
  return string.gsub(server_mac,"\n","")
end

function parse_data_from_pad(data,env)
	local ip_client = env.REMOTE_HOST
  syslog("ip client: "..ip_client)
  syslog("ip_client="..ip_client)
	--local mac_server = get_mac_by_ip(ip_client) -- 在这里为平板mac地址
  --syslog("mac_server: "..mac_server)
  
  local userid    = data.userid
  
	if(data.action == 0) then --用户扫二维码时，平板发出消息(消息中有client地址则从黑名单中移除,主要是为了将用户ID和平板mac地址记录下来)
        local result = 0
        local mac_phone = get_phone_mac_from_record_file_by_userid(userid)
        if(mac_phone ~= 0) then 
          --不是第一次登录,将mac地址从黑名单中移除(文件中已有完整的 userid:client_mac:server_mac映射关系)
          --将手机mac地址从黑名单中移除,并更新关系映射文件,以防止用户是从不同的平板电脑登录导致无法一对一投屏
          syslog("type=0,action=0,mac_phone="..mac_phone)
          local mac_server_history = get_server_mac_from_record_file_by_userid(userid)
          rm_rule(mac_phone,mac_server_history)
          --update_record_file(userid,"",mac_server)
          update_record_file(userid,mac_phone,mac_server)
          result = remove_mac_from_blacklist(mac_phone)
        else
          syslog("type=0,action=0,mac_phone=0")
          result = record_userid_servermac_to_file(userid,mac_server) -- 第一次登录,将用户ID和平板mac地址写入文件
        end
        return cjson.encode({errcode=result})
  elseif (data.action == 1) then --消息从平板发出，请求路由器将设备踢下线并将mac地址拉入黑名单
        local mac_phone = get_phone_mac_from_record_file_by_userid(userid)
        local mac_server_history = get_server_mac_from_record_file_by_userid(userid)
        if(mac_phone == 0) then -- 用户扫码,但是没有使用小程序连接wifi
          syslog("type=0,action=1,mac_phone=0")
          local result_delete_userid_entry  = delete_userid_entry(userid)
          return result_delete_userid_entry
        end
        syslog("type=0,action=1,mac_phone="..mac_phone)
        local result_dis = disassociate(mac_phone) --踢掉用户
    		local result_rm_rule = rm_rule(mac_phone,mac_server) --删除规则(本应是mac_client,为了方便测试改为data.client)
        syslog("mac_server: "..mac_server)
        syslog("mac_server_history: "..mac_server_history)
        if(mac_server == mac_server_history) then
          local result_add_mac_to_blacklist = add_mac_to_blacklist(mac_phone) --将用户加入黑名单
        end
        --local result_delete_userid_entry  = delete_userid_entry(userid)
        return result_dis
  elseif (data.action == 2) then --平板向路由器请求获取wifi的SSID及密码
        syslog("type=0,action=2")
        local cmd_get_wifi_ssid = "uci get wireless.default_ra.ssid"
        local cmd_get_wifi_key = "uci get wireless.default_ra.key"
        
        local result_ssid = sys.exec(cmd_get_wifi_ssid)
        local result_key  = sys.exec(cmd_get_wifi_key)
        local result  = {ssid= string.gsub(result_ssid,"\n",""),key= string.gsub(result_key,"\n","")}
        return cjson.encode(result)
  end
end

function handle_request(env)
	uhttpd.send("Status: 200 OK\r\n")
	uhttpd.send("Content-Type: application/json\r\n\r\n")
 
	local client_data = io.read("*all")
	local data = cjson.decode(client_data)

	if(data.type == 0) then
    syslog("type="..data.type)
    syslog("action="..data.action)
		local result = parse_data_from_pad(data,env)
    syslog("result="..result)
    uhttpd.send(result)
  elseif(data.type == 1) then
    syslog("token ="..data.token)
    local result = parse_data_from_phone(data,env)
    local res  = {err=tostring(result)}
    uhttpd.send(cjson.encode(res))
  end
end

