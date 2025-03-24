#!/usr/bin/env python
import gzip
import http.client
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Optional

# NOTE: splunklib must exist within github_forks/lib/splunklib for this
# example to run! To run this locally use `SPLUNK_VERSION=latest docker compose up -d`
# from the root of this repo which mounts this example and the latest splunklib
# code together at /opt/splunk/etc/apps/github_forks
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.modularinput import Argument, Event, EventWriter, Script, Scheme, ValidationDefinition, InputDefinition
# noinspection PyProtectedMember
from splunklib.client import StoragePassword, Input, KVStoreCollection
from splunklib.binding import HTTPError

class KennaAudit(Script):
    """Modular input class
    """
    mask = "<moved to secure store>"
    kv_name = "splunk_kenna_audit"  # used as kv collection store name

    def __init__(self):
        super().__init__()
        self.kv_store: Optional[KVStoreCollection] = None
        self._retries = 10  # total number ot tries to connect to KV store
        self._timeout_kv = 10  # number of seconds to wait between retries

    def get_scheme(self):
        """When Splunk starts, it looks for all the modular inputs defined by
        its configuration, and tries to run them with the argument --scheme.
        Splunkd expects the modular inputs to print a description of the
        input in XML on stdout. The modular input framework takes care of all
        the details of formatting XML and printing it. The user need only
        override get_scheme and return a new Scheme object.

        :return: scheme, a Scheme object
        """

        scheme = Scheme("Kenna Audit Logs")

        scheme.description = "Streams audit events from Cisco Vulnerability Aggregator aka Kenna Security"
        # If you set external validation to True, without overriding validate_input,
        # the script will accept anything as valid. Generally you only need external
        # validation if there are relationships you must maintain among the
        # parameters, such as requiring min to be less than max in this example,
        # or you need to check that some resource is reachable or valid.
        # Otherwise, Splunk lets you specify a validation string for each argument
        # and will run validation internally using that string.
        scheme.use_external_validation = True
        scheme.use_single_instance = True

        api_host = Argument("api_host")
        api_host.title = "Kenna API URL"
        api_host.data_type = Argument.data_type_string
        api_host.description = "Github user or organization that created the repository."
        api_host.required_on_create = True

        scheme.add_argument(api_host)

        api_key = Argument("api_key")  # this key will be encrypted and masked
        api_key.title = "Kenna API Key"
        api_key.data_type = Argument.data_type_string
        api_key.description = "API Key that allows access to the Kenna API and audit log."
        api_key.required_on_create = True
        scheme.add_argument(api_key)

        return scheme

    def validate_input(self, validation_definition: ValidationDefinition):
        """In this example we are using external validation to verify that the GitHub
        repository exists. If validate_input does not raise an Exception, the input
        is assumed to be valid. Otherwise, it prints the exception as an error message
        when telling splunkd that the configuration is invalid.

        When using external validation, after splunkd calls the modular input with
        --scheme to get a scheme, it calls it again with --validate-arguments for
        each instance of the modular input in its configuration files, feeding XML
        on stdin to the modular input to do validation. It is called the same way
        whenever a modular input's configuration is edited.

        :param validation_definition: a ValidationDefinition object
        """
        # TODO: test if api URL is reachable
        # api_host = validation_definition.parameters["api_host"]
        # api_key = validation_definition.parameters["api_key"]
        # try:
        #     connection = http.client.HTTPSConnection(api_host)
        #     headers = {
        #         'Content-type': 'application/json',
        #         'User-Agent': 'splunk-sdk-python',
        #         'X-Risk-Token': api_key,
        #     }
        #     connection.request("GET", "/connectors", headers=headers)
        #     response = connection.getresponse()
        #     body = response.read().decode()
        #     data = json.loads(body)
        # except Exception as e:
        #     raise ValueError(f"{e}")
        #
        # if "message" in data:
        #     raise ValueError(f"{data['message']}")

    def stream_events(self, inputs: InputDefinition, ew: EventWriter):
        """This function handles all the action: splunk calls this modular input
        without arguments, streams XML describing the inputs to stdin, and waits
        for XML on stdout describing events.

        If you set use_single_instance to True on the scheme in get_scheme, it
        will pass all the instances of this input to a single instance of this
        script.

        :param inputs: an InputDefinition object
        :param ew: an EventWriter object
        """
        ew.log("INFO", f"Starting app with {len(inputs.inputs)} inputs")
        if not self.connected_to_kv():
            ew.log("ERROR", f"App is not connected to a KVStore")
            return

        # Go through each input for this modular input
        for input_key, input_value in inputs.inputs.items():
            # Get fields from the InputDefinition object
            api_host = input_value["api_host"]
            api_key = input_value["api_key"]
            kind, input_name = input_key.split("://")
            username = f"{kind}___{input_name}"  # convert stanza name to username

            ew.log("INFO", f"Processing {input_name=}")

            # On first start API token is moved from webui input to splunk secure storage
            # then input is replaced with masked value self.mask
            self.secure_password(username, api_key, input_name)
            clear_password = self.get_password(username)

            kv_value = self.get_kv(key=input_name)
            last_run = kv_value.get("last_run")
            last_ingested_date = kv_value.get("last_ingested_date")
            ew.log("INFO", f"Last run was on {last_run} for date={last_ingested_date}")

            # Kenna API require at last one full day ago
            day_ago = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%d")
            if last_ingested_date and last_ingested_date == day_ago:
                ew.log("INFO", f"Skipping {input_name=} since last run")
                continue

            params = {"start_date": day_ago, "end_date": day_ago}
            query_string = urllib.parse.urlencode(params)
            headers = {
                'Accept': 'application/gzip',
                'User-Agent': 'splunk-sdk-python',
                'X-Risk-Token': clear_password,
            }
            url_path = f"/audit_logs?{query_string}"
            connection = http.client.HTTPSConnection(api_host)
            connection.request("GET", url_path, headers=headers)
            response = connection.getresponse()
            body = response.read()
            text = gzip.decompress(body)

            counter = 0
            for item in text.splitlines():
                # remove audit_log_event from events, all data is inside
                audit_event = json.loads(item).pop("audit_log_event")
                # convert individual event to JSON
                event_data = json.dumps(audit_event)
                # parse time and convert it to epoch timestamp
                event_time = datetime.strptime(
                    audit_event['occurred_at'], '%Y-%m-%d %H:%M:%S UTC'
                ).timestamp()
                event = Event(
                    stanza=input_key,
                    data=event_data,
                    time=f"{event_time:.3f}"  # format to add 3 digits after dot
                )
                # Tell the EventWriter to write this event
                ew.write_event(event)
                counter += 1
                self.upsert_kv(input_name, last_run=datetime.now(timezone.utc).isoformat(), last_ingested_date=day_ago)
            ew.log("INFO", f"Stop Processing {input_name=}. Processed {counter} events.")
        ew.log("INFO", f"Finish app run")

    def secure_password(self, username, password, input_name):
        if password != self.mask:
            self.encrypt_password(username, password)
            self.mask_password('api_key', input_name)

    def encrypt_password(self, username, password):
        try:
            # If the credential already exists, delete it.
            storage_password: StoragePassword
            for storage_password in self.service.storage_passwords:
                if storage_password.username == username:
                    self.service.storage_passwords.delete(username=storage_password.username)
                    break

            # Create the credential.
            self.service.storage_passwords.create(password, username)

        except Exception as e:
            raise Exception(
                f"An error occurred updating credentials. "
                f"Please ensure your user account has admin_all_objects and/or "
                f"list_storage_passwords capabilities.") from e

    def mask_password(self, password_field, input_name):
        kwargs = {password_field: self.mask}
        item: Input = self.service.inputs[input_name]
        item.update(**kwargs)

    def get_password(self, username):
        storage_password: StoragePassword
        for storage_password in self.service.storage_passwords:
            if storage_password.username == username:
                return storage_password.clear_password

    def connected_to_kv(self):
        while self._retries:
            try:
                self.kv_store = self.service.kvstore[self.kv_name]
                self.kv_store.data.query(query={}, limit=1)  # test that KV store is reachable
                return True
            except HTTPError:
                self._retries -= 1
                time.sleep(self._timeout_kv)
                continue
        return False

    def upsert_kv(self, key: str, **kwargs):
        if not self.get_kv(key):
            self.kv_store.data.insert(data=json.dumps({"_key": key, **kwargs}))
        else:
            self.kv_store.data.update(id=key, data=json.dumps(kwargs))

    def get_kv(self, key: str) -> dict:
        # noinspection PyTypeChecker
        values: list = self.kv_store.data.query(query={"_key": key})
        if values:
            return values[0]
        return dict()


if __name__ == "__main__":
    sys.exit(KennaAudit().run(sys.argv))
