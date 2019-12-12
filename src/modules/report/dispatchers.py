import logging
import os
import requests
from __main__ import config


class HTTPDispatcher(object):
    def dispatch(self, report):
        logging.debug('Dispatching report via http')
        dispatchMethod = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_METHOD',
            'POST'
        ).upper()
        dispatchURL = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_URL',
            'https://localhost/'
        )
        dispatchAUTHUSERNAME = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_USERNAME',
            ''
        )
        dispatchAUTHPASSWORD = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_PASSWORD',
            ''
        )
        try:
            r = requests.request(
                dispatchMethod,
                dispatchURL,
                json=report,
                headers={'Content-Type': 'application/json'},
                auth=(dispatchAUTHUSERNAME, dispatchAUTHPASSWORD)
            )
            r.raise_for_status()
            logging.info('\nReport was dispatched to: {url}'.format(url=dispatchURL))
            if dispatchAUTHUSERNAME:
                logging.info('\nWe used password and username on this request')
            logging.debug(
                "\tResponse Code: {status}\n\tResponse Data:\n{data}".format(
                    status=r.status_code,
                    data=r.text
                )
            )
        except requests.HTTPError as e:
            # specific http exceptions
            logging.error(
                "\nCould not dispatch report using HTTP {method} to {url} with auth ({username}:{password})\nResponse Code: {status}".format(
                    status=r.status_code,
                    url=dispatchURL,
                    method=dispatchMethod,
                    username=dispatchAUTHUSERNAME,
                    password=dispatchAUTHPASSWORD
                )
            )
        except Exception as e:
            # default all exceptions
            logging.error("\nCould not dispatch report using HTTP {method} to {url} - {error}".format(
                method=dispatchMethod,
                url=dispatchURL,
                error=e
            ))

class STDOUTDispatcher(object):
    def dispatch(self, report):
        logging.debug('Dispatching report via stdout')
        if config.report == "plain":
            logging.info("\n{div}".format(div="-" * 10))
        print(report)
