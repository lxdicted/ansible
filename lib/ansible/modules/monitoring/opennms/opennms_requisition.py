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
module: opennms_requisition
author:
  - Danny Sonnenschein
version_added: "2.8"
short_description: Manage OpenNMS requisitions
description:
  - Create, synchronize, delete OpenNMS requisitions via REST API.
options:
  url:
    description:
      - The OpenNMS REST API  URL
    default: http://localhost:8980/opennms/
  url_username:
    description:
      - The OpenNMS API user name.
    default: admin
  url_password:
    description:
      - The OpenNMS API user's password.
    default: admin
  synchronize:
    description:
      - If the requisition should be synchronized
    type: bool
    default: false
  rescan_existing:
    description:
      - If existing node should be rescaned during synchronization
    type: bool
    default: false
  date_stamp:
    description:
      - Timestamp of requisition creation
    required: true
  state:
    description:
      - State of the requisition
    choices: [ absent, present ]
    default: present
  name:
    description:
      - The name of the requisition.
    required: true
'''

EXAMPLES = '''
    - name: Create an empty requisition
      opennms_requisition:
        url_username: ansible
        url_password: password
        name: ansible

    - name: Add a node to the requisition
      opennms_node:
        url: https://opennms.example.com/opennms
        name: nodename
        name: ansible

    - name: Synchronize the requisition
      opennms_requisition:
        url: https://opennms.example.com/opennms
        url_username: admin
        url_password: admin
        name: ansible
        rescan_existing: false
        synchronize: true

    - name: Delete the requisition
      opennms_requisition:
        name: ansible
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


def opennms_requisition_exists(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    requisition_exists = False
    requisition = {}

    r, info = fetch_url(module, "%s/rest/requisitions/%s" % (data['url'], data['name']), headers=headers, method="GET")
    if info['status'] == 200:
        requisition_exists = True
        requisition = json.loads(r.read())

    return requisition_exists, requisition


def opennms_requisition_synchronize(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    result = {}
    r, info = fetch_url(module, '%s/rest/requisitions/%s/import' % (data['url'], data['name']), headers=headers, method='PUT')
    if info['status'] == 202:
        result['msg'] = "Requisition '%s' synchronized" % data['name']
        result['changed'] = True
    elif info['status'] == 204:
        result['msg'] = "Requisition '%s' already synchronized" % data['name']
        result['changed'] = False
    else:
        module.fail_json(msg="Synchronization of requisition '%s' failed (HTTP status: %i)" % (data['name'], info['status']))

    return result


def opennms_requisition_create(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    # test if requisition already exists
    requisition_exists, requisition = opennms_requisition_exists(module, data)

    result = {}
    if requisition_exists is True:
        result['msg'] = "Requisition '%s' not modified" % data['name']
        result['changed'] = False
    else:
        content = {'foreign-source': data['name'], 'node': []}

        request_uri = "%s/rest/requisitions" % data['url']
        r, info = fetch_url(module, request_uri, headers=headers, method='POST', data=json.dumps(content))
        if info['status'] == 202:
            result['msg'] = "Requisition '%s' created" % data['name']
            result['changed'] = True
        else:
            module.fail_json(msg="Creation of requisition '%s' failed (HTTP status: %i)" % (data['name'], info['status']))

    return result


def opennms_requisition_delete(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    # test if requisition exists
    requisition_exists, requisition = opennms_requisition_exists(module, data)

    result = {}
    if requisition_exists is True:
        request_uri = '%s/rest/requisitions/%s' % (data['url'], data['name'])
        r, info = fetch_url(module, '%s/rest/requisitions/%s' % (data['url'], data['name']), headers=headers, method='DELETE')
        if info['status'] == 202:
            result['msg'] = "Requisition '%s' deleted" % data['name']
            result['changed'] = True

            request_uri = '%s/rest/requisitions/deployed/%s' % (data['url'], data['name'])
            fetch_url(module, request_uri, headers=headers, method='DELETE')
            request_uri = '%s/rest/foreignSources/%s' % (data['url'], data['name'])
            fetch_url(module, request_uri, headers=headers, method='DELETE')
            request_uri = '%s/rest/foreignSources/deployed/%s' % (data['url'], data['name'])
            fetch_url(module, request_uri, headers=headers, method='DELETE')
        else:
            module.fail_json(msg="Deletion of requisition '%s' failed (HTTP status: %i)" % (data['name'], info['status']))
    else:
        result['msg'] = "Requisition '%s' not found" % data['name']
        result['changed'] = False

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
        name=dict(aliases=['requisition'], type='str', required=True),
        date_stamp=dict(type='str', required=False),
        synchronize=dict(type='bool', default=False),
        rescan_existing=dict(type='bool', default=False)
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[['url_username', 'url_password']]
    )

    if module.params['state'] == 'absent':
        result = opennms_requisition_delete(module, module.params)
    elif module.params['state'] == 'present':
        result = opennms_requisition_create(module, module.params)
        if module.params['synchronize']:
            result = opennms_requisition_synchronize(module, module.params)

    module.exit_json(**result)

    return


def main():
    run_module()


if __name__ == '__main__':
    main()
