function m2s_wirednet(lip, mac)
   if (mac == 'aa:bb:cc:dd:ee:ff') then
      return '192.168.0.2'
   end
   return nil
end

function m2s_wifinet(lip, mac)
   if (mac == 'ff:ee:dd:cc:aa:bb') then
      return '192.168.1.2'
   end
   return nil
end

function get_ip_stem(ip)
   local s, e, ipstem = ip:find('(%d+%.%d+%.%d+%.)%d+')
   return ipstem
end

function assign_ip(dm, sipfn, lip, mac, cid, rlo, rhi)
   -- Handle static assignments.
   if sipfn then
      local sip = sipfn(lip, mac)
      if sip then
         print('Statically assigned a lease by MAC.')
         dhcpmsg_set_ip(dm, sip)
         dhcpmsg_set_lease_time(dm, 84000)
         return true
      end
   end
   -- Check to see if an non-expired lease exists for this device.  If it
   -- does, then reassign it.
   local curip = dhcp_get_current_lease(lip, cid)
   if curip then
      print('Got a current lease.')
      dhcpmsg_set_ip(dm, curip)
      dhcpmsg_set_lease_time(dm, 900)
      return true
   end

   -- Go through the range list until a free slot is found.
   if rlo > rhi then
      rlo, rhi = rhi, rlo
   end
   local ipstem = get_ip_stem(lip)
   for i = rlo, rhi, 1 do
      tip = ipstem .. i
      if not dhcp_is_ip_leased(lip, tip, cid) then
         print('Assigned a new lease.')
         dhcpmsg_set_ip(dm, tip)
         dhcpmsg_set_lease_time(dm, 900)
         return true
      end
   end
   return false
end

function common_reply_assign(dm, lip, rip, mac, cid)
   if (lip == '192.168.0.1') then
      if not assign_ip(dm, m2s_wirednet, lip, mac, cid, 100, 250) then
         return false
      end
   elseif (lip == '192.168.1.1') then
      if not assign_ip(dm, m2s_wifinet, lip, mac, cid, 100, 250) then
         return false
      end
   end
   return true
end

function common_reply_info(dm, lip, rip, mac, cid)
   if (lip == '192.168.0.1') then
      dhcpmsg_set_broadcast(dm, '192.168.0.255')
      dhcpmsg_set_routers(dm, '192.168.0.1')
      dhcpmsg_set_dns(dm, '192.168.0.1')
      dhcpmsg_set_ntp(dm, '192.168.0.1')
   elseif (lip == '192.168.1.1') then
      dhcpmsg_set_broadcast(dm, '192.168.1.255')
      dhcpmsg_set_routers(dm, '192.168.1.1')
      dhcpmsg_set_dns(dm, '192.168.0.1')
   end
   dhcpmsg_set_domain_name(dm, "example.net")
   dhcpmsg_set_subnet(dm, '255.255.255.0')
end

function common_reply(dm, lip, rip, mac, cid, do_assign)
   if do_assign then
      local r = common_reply_assign(dm, lip, rip, mac, cid)
      if not r then
         return false
      end
   end
   common_reply_info(dm, lip, rip, mac, cid)
   return true
end

function dhcp_reply_discover(dm, lip, rip, mac, cid)
   return common_reply(dm, lip, rip, mac, cid, true)
end

function dhcp_reply_request(dm, lip, rip, mac, cid)
   return common_reply(dm, lip, rip, mac, cid, true)
end

function dhcp_reply_inform(dm, lip, rip, mac, cid)
   return common_reply(dm, lip, rip, mac, cid, false)
end

