from time import sleep

import twitter
from typing import Dict, List, Type

def lol(string):
    print(string)
    return False

class DM:
    def __init__(self: object, id: int, created_timestamp: int, text: str, sender_id: int, recipient_id: int):
        self.id = id
        self.created_timestamp = created_timestamp
        self.text = text
        self.sender_id = sender_id
        self.recipient_id = recipient_id

    @classmethod
    def from_dict(self, dm: dict):
        return DM(id=int(dm.get('id')),
                  created_timestamp=int(dm.get('created_timestamp')),
                  text=dm.get('message_create').get('message_data').get('text').lower().strip(),
                  sender_id=int(dm.get('message_create').get('sender_id')),
                  recipient_id=int(dm.get('message_create').get('target').get('recipient_id'))
                  )

    @classmethod
    def from_DirectMessage(self, dm: twitter.DirectMessage):
        return DM(id=int(dm.id),
                  created_timestamp=int(dm.created_at),
                  text=dm.text.lower().strip(),
                  sender_id=int(dm.sender_id),
                  recipient_id=int(dm.recipient_id)
                  )

    def __repr__(self):
        return "{id: %d, created_timestamp: %d, text: %s, sender_id: %d, recipient_id: %d}\n" % (
            self.id, self.created_timestamp, self.text, self.sender_id, self.recipient_id)


# valid response is not sent by us,
def is_valid_response_dm(self_sent_dm: DM, response_dm: DM) -> bool:
    # print(1, response_dm.sender_id == self_sent_dm.recipient_id)
    # print(2, response_dm.recipient_id == self_sent_dm.sender_id)
    # print(3, response_dm.created_timestamp > self_sent_dm.created_timestamp)
    # print(4, (response_dm.text == "yes" or response_dm.text == "no"))
    return response_dm.sender_id == self_sent_dm.recipient_id and \
           response_dm.recipient_id == self_sent_dm.sender_id and \
           response_dm.created_timestamp > self_sent_dm.created_timestamp and \
           (response_dm.text == "yes" or response_dm.text == "no")


def twitter_proxy(screen_name: str) -> bool:
    try:
        print("python sending message to @%s" % screen_name)
        api = twitter.Api(consumer_key='aRKCgM5tZsodzZkWXN1cAoiIn',
                          consumer_secret='QGlanYuQ2UOjZBCDhzufAIDTzXP9kVXOGAF7Y1ZY2OL11gMICG',
                          access_token_key='1047285121789747200-MoUfcQbJaxFDalzfJxsXbAcDAyyCRd',
                          access_token_secret='5endSxXn4D6httbhMjxWkiOFiYhSyl017mTjLStZRtpk5')

        target_user_id = api.GetUser(screen_name=screen_name).id
        raw_sent_dm = api.PostDirectMessage('A TC is requesting access. Respond with "yes" or "no" within 5 mins.', user_id=target_user_id)
        self_sent_dm = DM.from_DirectMessage(raw_sent_dm)
        print("DM sent", self_sent_dm)

        # keep polling until there is a dm with time a response of "yes" or "no" after our request, trying for up to 5 mins
        for _ in range(15):
            sleep(20)  # rate limit
            dms = api.GetDirectMessages(return_json=True)
            print("Fetching DMs")
            response_dms = [DM.from_dict(dm) for dm in dms.get('events')]
            response_dms = [dm for dm in response_dms if is_valid_response_dm(self_sent_dm, dm)]
            response_dms.sort(key=lambda dm: dm.created_timestamp)

            print("all dms      \n", dms)
            print("filtered dms \n", response_dms)
            if len(response_dms) == 0:
                continue

            if response_dms[0].text == "yes":  # text is guaranteed to be "yes" or "no" by parse_dms
                return True
            elif response_dms[0].text == "no":
                return False

        return False #return false if timeout
    except Exception as e:
        print(e)

# res = twitter_proxy("nsshuman")