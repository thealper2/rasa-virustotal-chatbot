from typing import Any, Text, Dict, List

from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher

import json
import requests

API_KEY = "<YOUR_VIRUSTOTAL_API_KEY_HERE>"

class ActionCheckHash(Action):
    def name(self) -> Text:
        return "action_vt_check_hash"

    def run(self, dispatcher: CollectingDispatcher, 
            tracker: Tracker, 
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        
        target_hash = tracker.get_slot('target_hash')
        params = {"apikey": API_KEY, "resource": target_hash}
        vt_url = "https://www.virustotal.com/vtapi/v2/file/report"

        try:
            vt_response = requests.get(vt_url, params=params)
            if vt_response.status_code == 200:
                vt_keys = vt_response.json()
                if 'data' in vt_keys and 'attributes' in vt_keys['data']:
                    if vt_keys.get('positives') > 0:
                        message = f"It seems this {target_hash} is malicious."
                    else:
                        message = f"It seems this {target_hash} is benign."
                    dispatcher.utter_message(message)
                else:
                    dispatcher.utter_message("Sorry, I couldn't find information about this hash.")
            else:
                dispatcher.utter_message("Sorry, there was an error processing your request.")
        except Exception as e:
            dispatcher.utter_message("Sorry, there was an error processing your request.")

        return []

class ActionCheckURL(Action):
    def name(self):
        return "action_vt_check_url"

    def run(self, dispatcher: CollectingDispatcher, 
            tracker: Tracker, 
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        
        target_url = tracker.get_slot('target_url')
        params = {"apikey": API_KEY, "resource": target_url}
        vt_url = "https://www.virustotal.com/vtapi/v2/url/report"

        try:
            vt_response = requests.get(vt_url, params=params)
            if vt_response.status_code == 200:
                vt_keys = vt_response.json()
                if 'data' in vt_keys and 'attributes' in vt_keys['data']:
                    if vt_keys.get('positives') > 0:
                        message = f"It seems this {target_url} is malicious."
                    else:
                        message = f"It seems this {target_url} is benign."
                    dispatcher.utter_message(message)
                else:
                    dispatcher.utter_message("Sorry, I couldn't find information about this url.")
            else:
                dispatcher.utter_message("Sorry, there was an error processing your request.")
        except Exception as e:
            dispatcher.utter_message("Sorry, there was an error processing your request.")

        return []
