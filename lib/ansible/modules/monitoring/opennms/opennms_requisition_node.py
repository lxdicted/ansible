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
module: opennms_requisition_node
author:
  - Danny Sonnenschein
version_added: "2.8"
short_description: Manage OpenNMS nodes
description:
  - Create, delete OpenNMS nodes via REST API.
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
  state:
    description:
      - State of the requisition
    choices: [ absent, present ]
    default: present
  requisition:
    description:
      - Name of the node's requisition.
  foreign_id:
    description:
      - Foreign ID of the node
  node_label:
    description:
      - Label of the node
    required: true
  location:
    description:
      - Minion location
  parent_foreign_id:
    description:
      - Parent foreign ID
  parent_node_label:
    description:
      - Parent node label
  parent_foreign_source:
    description:
      - Parent foreign source (aka requisition)
'''

EXAMPLES = '''
    - name: Create a node in requisition ansible (on localhost)
      opennms_requisition_node:
        opennms_username: admin
        opennms_password: admin
        foreign_id: "{{ ansible_date_time.epoch }}"
        node_label: "{{ ansible_fqdn }}"
        requisition: ansible

    - name: Add another node to requisition with parent node
      opennms_requisition_node:
        delegate_to: localhost
        opennms_url: https://opennms.org/opennms/
        opennms_username: admin
        opennms_password: admin
        foreign_id: "{{ ansible_machine_id }}"
        node_label: "{{ ansible_fqdn }}"
        parent_foreign_id: "{{ hostvars['gateway']['ansible_machine_id'] }}"
        parent_foreign_source: manual-nightmare
        requisition: ansible

    - name: Add an interface to node
      opennms_requisition_interface:
        delegate_to: localhost
        opennms_url: https://opennms.org/opennms/
        opennms_username: admin
        opennms_password: admin
        requisition: ansible
        foreign_id: "{{ ansible_machine_id }}"
        descr: eth0
        ip-addr: 192.168.179.1

    - name: Delete a node in requisition ansible (on localhost)
      opennms_requisition_node:
        delegate_to: localhost
        opennms_url: https://opennms.org/opennms/
        opennms_username: admin
        opennms_password: admin
        foreign_id: "{{ ansible_machine_id }}"
        requisition: ansible
        state: absent
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

    # foreign_id is required here and unique within requisition
    request_uri = '%s/rest/requisitions/%s/nodes/%s' % (data['url'], data['requisition'], data['foreign_id'])

    r, info = fetch_url(module, request_uri, headers=headers, method="GET")
    if info['status'] == 200:
        node_exists = True
        node = json.loads(r.read())

    return node_exists, node


def opennms_requisition_node_delete(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    node_exists, node = opennms_requisition_node_exists(module, data)

    result = {}
    if node_exists is False:
        result['msg'] = "Node '%s' not modified" % data['node_label']
        result['changed'] = False
    else:
        request_uri = '%s/rest/requisitions/%s/nodes/%s' % (data['url'], data['requisition'], node['foreign-id'])
        r, info = fetch_url(module, request_uri, headers=headers, method='DELETE')
        if info['status'] == 202 or info['status'] == 204:
            result['msg'] = "Node '%s' deleted from requisition %s" % (data['node_label'], data['requisition'])
            result['changed'] = True
        else:
            module.fail_json(msg="Deletion of node '%s' from requisition '%s' failed (HTTP status: %i)" % (data['node_label'], data['requisition'], info['status']))

    return result


def opennms_requisition_node_create(module, data):

    # define http headers
    headers = opennms_headers(module, data)

    node_exists, requisition = opennms_requisition_node_exists(module, data)

    result = {}
    if node_exists is True:
        result['msg'] = "Node '%s' not modified" % data['node_label']
        result['changed'] = False
    else:
        content = {
            'foreign-id':            data['foreign_id'],
            'node-label':            data['node_label'],
            'parent-foreign-id':     data['parent_foreign_id'],
            'parent-node-label':     data['parent_node_label'],
            'parent-foreign-source': data['parent_foreign_source'],
            'location':              data['location'],
        }

        request_uri = "%s/rest/requisitions/%s/nodes" % (data['url'], data['requisition'])
        r, info = fetch_url(module, request_uri, headers=headers, method='POST', data=json.dumps(content))
        if info['status'] == 202:
            result['msg'] = "Node '%s' created in requisition '%s'" % (data['foreign_id'], data['requisition'])
            result['changed'] = True
        else:
            module.fail_json(msg="Creation of node '%s' in requisition '%s' failed (HTTP status: %i)" % (data['node_label'], data['requisition'], info['status']))

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
        location=dict(type='str', default=None),
        parent_foreign_id=dict(type='str', default=None),
        parent_node_label=dict(type='str', default=None),
        parent_foreign_source=dict(type='str', default=None),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[['url_username', 'url_password']],
        mutually_exclusive=[('parent_foreign_id', 'parent_node_label')],
        required_if=(
            ('state', 'present', ['node_label']),
        ),
        required_one_of=[['node_label', 'foreign_id']],
    )

    result = {}
    if module.params['state'] == 'absent':
        result = opennms_requisition_node_delete(module, module.params)
    elif module.params['state'] == 'present':
        result = opennms_requisition_node_create(module, module.params)

    module.exit_json(**result)

    return


def main():
    run_module()


if __name__ == '__main__':
    main()
