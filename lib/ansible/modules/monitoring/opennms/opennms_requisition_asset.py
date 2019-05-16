#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019, Danny Sonnenschein
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt

# from __future__ import absolut_import, print_function

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'metadata_version': '1.1'
}

DOCUMENTATION = '''
---
module: opennms_requisition_asset
author:
  - Danny Sonnenschein
version_added: "2.8"
short_description: Manage OpenNMS assets for a given node
description:
  - Add or delete OpenNMS assets for given node via REST API.
  - Please see OpenNMS documentation for a full list of available
  - assets.
options:
  url:
    description:
      - The OpenNMS REST API URL
    default: http://localhost:8980/opennms/
  url_username:
    description:
      - The OpenNMS API user name.
    default: admin
  url_password:
    description:
      - The OpenNMS API user's password.
    default: admin
  state:
    description:
      - State of the asset. If state is 'absent', the asset will be deleted.
    choices: [ absent, present ]
    default: present
  requisition:
    description:
      - Name of the node's requisition.
    required: true
  foreign_id:
    description:
      - Foreign ID of the node
  node_label:
    description:
      - Label of the node
    required: true
  name:
    description:
      - The asset name.
    required: true
  value:
    description:
      - The asset value.
    required: true
'''

EXAMPLES = '''
  - name: Update lastModified assets
    opennms_asset:
      delegate_to: localhost
      requisition: requisition-name
      node_label: "{{ ansible_fqdn }}"
    with_items:
    - { "name": "lastModifiedBy",   "value": "{{ ansible_user_gecos }}" }
    - { "name": "lastModifiedDate", "value": "{{ ansible_date_time.date }}" }
'''

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, url_argument_spec
from ansible.module_utils._text import to_native
from ansible.module_utils._text import to_text

__metaclass__ = type


def opennms_headers(module, data):

    headers = {
        'content-type': 'application/json; charset=utf8',
        'accept': 'application/json'
    }

    module.params['force_basic_auth'] = True

    return headers


def opennms_requisition_node_exists(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    node_exists = False
    node = {}

    request_uri = '%s/rest/requisitions/%s/nodes' % (data['url'], data['requisition'])
    if data['foreign_id'] is not None:
        request_uri += '/%s' % data['foreign_id']

    r, info = fetch_url(module, request_uri, headers=headers, method="GET")
    if info['status'] == 200:
        nodes = json.loads(r.read())
        if data['foreign_id'] is not None:
            node = nodes
            node_exists = True
        elif nodes['count'] is not None:
            for n in nodes['node']:
                if n['node-label'] == data['node_label']:
                    node_exists = True
                    node = n

    return node_exists, node


def opennms_requisition_node_asset_exists(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    asset_exists = False
    asset = {}

    node_exists, node = opennms_requisition_node_exists(module, data)
    if node_exists is False:
        if data['foreign_id'] is None:
            label = data['node_label']
        else:
            label = data['foreign_id']
        module.fail_json(msg="Cannot find node '%s' in requisition '%s'" % (label, data['requisition']))

    for a in node['asset']:
        if a['name'] == data['name']:
            asset_exists = True
            asset = a

    return asset_exists, asset, node['foreign-id']


def opennms_requisition_node_asset_delete(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    asset_exists = False
    asset = {}

    asset_exists, asset, foreign_id = opennms_requisition_node_asset_exists(module, data)

    result = {}
    if asset_exists is False:
        result['msg'] = "Asset '%s' not defined for node '%s' modified" % (data['name'], foreign_id)
        result['changed'] = False
    else:

        request_uri = '%s/rest/requisitions/%s/nodes/%s/assets/%s' % (data['url'], data['requisition'], foreign_id, data['name'])
        r, info = fetch_url(module, request_uri, headers=headers, method='DELETE')
        if info['status'] == 202 or info['status'] == 204:
            result['msg'] = "Asset '%s' for node '%s' deleted from requisition '%s'" % (data['name'], foreign_id, data['requisition'])
            result['changed'] = True
        else:
            module.fail_json(msg="Deletion of asset '%s' for node '%s' from requisition '%s' failed (HTTP status: %i)" % (data['name'], foreign_id, data['requisition'], info['status']))

    return result


def opennms_requisition_node_asset_set(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    asset_exists, asset, foreign_id = opennms_requisition_node_asset_exists(module, data)

    result = {}
    if asset_exists is True and asset['value'] == data['value']:
        result['msg'] = "Asset '%s' for node '%s' in requisition '%s' not modified" % (data['name'], foreign_id, data['requisition'])
        result['changed'] = False
    else:
        content = {"name": data['name'], "value": data['value']}

        request_uri = "%s/rest/requisitions/%s/nodes/%s/assets" % (data['url'], data['requisition'], foreign_id)
        r, info = fetch_url(module, request_uri, headers=headers, method='POST', data=json.dumps(content))
        if info['status'] == 202:
            result['msg'] = "Asset '%s' for node '%s' created in requisition '%s'" % (data['name'], foreign_id, data['requisition'])
            result['changed'] = True
        else:
            module.fail_json(msg="Creation of asset '%s' for node '%s' in requisition '%s' failed (HTTP status: %i)" % (data['name'], foreign_id, data['requisition'], info['status']))

    return result


def run_module():
    # use the predefined argument spec for url
    argument_spec = url_argument_spec()
    # remove unnecessary arguments
    del argument_spec['force']
    del argument_spec['http_agent']
    argument_spec.update(
        state=dict(choices=['present', 'absent'], default='present'),
        url=dict(aliases=['opennms_url'], default='http://localhost:8980/opennms'),
        url_username=dict(aliases=['opennms_user'], default='admin'),
        url_password=dict(aliases=['opennms_password'], default='admin', no_log=True),
        requisition=dict(type='str', required=True),
        foreign_id=dict(type='str'),
        node_label=dict(type='str'),
        name=dict(type='str', required=True),
        value=dict(type='str', default=None),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[['url_username', 'url_password']],
        required_one_of=[['node_label', 'foreign_id']],
    )

    result = {}
    if module.params['state'] == 'absent':
        result = opennms_requisition_node_asset_delete(module, module.params)
    elif module.params['state'] == 'present':
        result = opennms_requisition_node_asset_set(module, module.params)

    module.exit_json(**result)

    return


def main():
    run_module()


if __name__ == '__main__':
    main()
