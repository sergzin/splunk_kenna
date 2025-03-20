#!/usr/bin/env python
import datetime
import gzip
import http.client
import json
import logging
import os
import sys
import urllib.parse

# NOTE: splunklib must exist within github_forks/lib/splunklib for this
# example to run! To run this locally use `SPLUNK_VERSION=latest docker compose up -d`
# from the root of this repo which mounts this example and the latest splunklib
# code together at /opt/splunk/etc/apps/github_forks
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.modularinput import Argument, Event, EventWriter, Script, Scheme, ValidationDefinition, InputDefinition


class KennaAudit(Script):
    """Modular input class
    """

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

        api_key = Argument("api_key")
        api_key.title = "Kenna API Key"
        api_key.data_type = Argument.data_type_string
        api_key.description = "API Key that allows access to the Kenna API and audit log."
        api_key.required_on_create = True
        scheme.add_argument(api_key)

        return scheme

    def validate_input(self, validation_definition: ValidationDefinition):
        """In this example we are using external validation to verify that the Github
        repository exists. If validate_input does not raise an Exception, the input
        is assumed to be valid. Otherwise it prints the exception as an error message
        when telling splunkd that the configuration is invalid.

        When using external validation, after splunkd calls the modular input with
        --scheme to get a scheme, it calls it again with --validate-arguments for
        each instance of the modular input in its configuration files, feeding XML
        on stdin to the modular input to do validation. It is called the same way
        whenever a modular input's configuration is edited.

        :param validation_definition: a ValidationDefinition object
        """
        # test if api URL is reachable
        api_host = validation_definition.parameters["api_host"]
        api_key = validation_definition.parameters["api_key"]
        try:
            connection = http.client.HTTPSConnection(api_host)
            headers = {
                'Content-type': 'application/json',
                'User-Agent': 'splunk-sdk-python',
                'X-Risk-Token': api_key,
            }
            connection.request("GET", "/connectors", headers=headers)
            response = connection.getresponse()
            body = response.read().decode()
            data = json.loads(body)
        except Exception as e:
            raise ValueError(f"{e}")

        if "message" in data:
            raise ValueError(f"{data['message']}")

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
        logging.info("Starting stream events")
        # Go through each input for this modular input
        for input_name, input_item in list(inputs.inputs.items()):
            # Get fields from the InputDefinition object
            api_host = input_item["api_host"]
            api_key = input_item["api_key"]

            # Hint: API auth required?, get a secret from passwords.conf
            # self.service.namespace["app"] = input_item["__app"]
            # api_token = self.service.storage_passwords["github_api_token"].clear_password

            day_ago = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)).strftime("%Y-%m-%d")

            params = {"start_date": day_ago, "end_date": day_ago}
            query_string = urllib.parse.urlencode(params)
            headers = {
                'Accept': 'application/gzip',
                'User-Agent': 'splunk-sdk-python',
                'X-Risk-Token': api_key,
            }
            url_path = f"/audit_logs?{query_string}"
            connection = http.client.HTTPSConnection(api_host)
            connection.request("GET", url_path, headers=headers)
            response = connection.getresponse()
            body = response.read()
            text = gzip.decompress(body)

            for item in text.splitlines():
                # remove audit_log_event from events, all data is inside
                audit_event = json.loads(item).pop("audit_log_event")
                # convert individual event to JSON
                event_data = json.dumps(audit_event)
                # parse time and convert it to epoch timestamp
                event_time = datetime.datetime.strptime(
                    audit_event['occurred_at'], '%Y-%m-%d %H:%M:%S UTC'
                ).timestamp()
                event = Event(
                    stanza=input_name,
                    data=event_data,
                    time=f"{event_time:.3f}"  # format to add 3 floating points
                )

                # Tell the EventWriter to write this event
                ew.write_event(event)


if __name__ == "__main__":
    sys.exit(KennaAudit().run(sys.argv))
