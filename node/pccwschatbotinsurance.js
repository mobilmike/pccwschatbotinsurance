/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request');
  
var fs = require('fs');

var httpport = 5040;
var httpsport = 5041;

var hskey = fs.readFileSync('../../key/domain-key.txt');
var hscert = fs.readFileSync('../../key/domain-crt.txt')

var options = {
    key: hskey,
    cert: hscert
};
  
  
var app = express();
app.set('port', process.env.PORT || httpport);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

var store = require('data-store')('my-app');
/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');
  
const period_text = "2017 年04 月 30日 – 2018年04月 30日";

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s",
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

    sendTextMessage(senderID, "Quick reply tapped");
    return;
  }

  if (messageText) {
	
    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
	
	if ((messageText.search("保單")>=0) && (messageText.search("查")>=0)){
	   sendTextMessage(senderID,'您現擁有的保險計劃包括:');
	   sendGenericPolicyMessage(senderID);

	}
	else if ((messageText.search("其他")>=0) && ((messageText.search("計劃")>=0) || (messageText.search("保險")>=0) )){
	   sendTextMessage(senderID,'很好!為提供更適合您的方案, 請核對您的個人基本信息。');
	   sendGenericPolicy3AMessage(senderID);
	}
	else if (messageText.search("住院了")>=0){
	   sendTextMessage(senderID,'需耍為您申請理賠嗎?');
	   sendTextMessage(senderID,'您所購買的新光人壽New Health健康保險主要給付項目：住院醫療費用保險金\n一、醫師指示用藥。\n二、血液（非緊急傷病必要之輸血）。\n三、掛號費及證明文件。\n四、來往醫院之救護車費。\n五、超等住院之病房費差額。\n六、管灌飲食以外之膳食費。\n七、特別護士以外之護理費。\n八、超過全民健康保險給付之住院醫療費用，但不包括下列費用:\n1、藥癮治療、預防性手術、變性手術。\n2、成藥。\n3、指定醫師費。\n4、人體試驗，但經全民健康保險專案批准給付者不在此限。\n*詳細內容以保險單條款為準');
	}
	else if (messageText.search("好")==0){
	   sendTextMessage(senderID,'請以(XXXX年XX月XX日XX時)格式輸入事故日期');
	}
	else if ((messageText.search("年")>=0) && (messageText.search("月")>=0) && (messageText.search("日")>=0)){
		store.set('policydate', messageText);
	   sendTextMessage(senderID,'就診身分是健保, 自費或是其他?');
	}
	else if ((messageText.search("健保")==0) || (messageText.search("自費")==0) || (messageText.search("其他")==0)){
		store.set('policytype', messageText);
	   sendTextMessage(senderID,'就診之醫療院所是?');
	}
	else if (messageText.search("醫院")>=0){
	   store.set('hospital', messageText);
	   sendTextMessage(senderID,'請上傳您的診斷書');
	}
	else {
		switch (messageText.replace(/[^\w\s]/gi, '').trim().toLowerCase()) {
		  case 'hello':
		  case 'hi':
			sendHiMessage(senderID);
			break;

		 /* case 'image':
			requiresServerURL(sendImageMessage, [senderID]);
			break;

		  case 'gif':
			requiresServerURL(sendGifMessage, [senderID]);
			break;

		  case 'audio':
			requiresServerURL(sendAudioMessage, [senderID]);
			break;

		  case 'video':
			requiresServerURL(sendVideoMessage, [senderID]);
			break;

		  case 'file':
			requiresServerURL(sendFileMessage, [senderID]);
			break;

		  case 'button':
			sendButtonMessage(senderID);
			break;

		  case 'generic':
			requiresServerURL(sendGenericMessage, [senderID]);
			break;

		  case 'receipt':
			requiresServerURL(sendReceiptMessage, [senderID]);
			break;

		  case 'quick reply':
			sendQuickReply(senderID);
			break;

		  case 'read receipt':
			sendReadReceipt(senderID);
			break;

		  case 'typing on':
			sendTypingOn(senderID);
			break;

		  case 'typing off':
			sendTypingOff(senderID);
			break;

		  case 'account linking':
			requiresServerURL(sendAccountLinking, [senderID]);
			break;*/

		  default:
			sendTextMessage(senderID, '你好!  請問有什麼需要幫助呢?');
		}
	  } 
  }
  else if (messageAttachments) {
	sendTextMessage(senderID,'感謝您的合作。請核對您的理賠申請及預定給付方式。');
	sendGenericPaymentMessage(senderID);
    //sendTextMessage(senderID, "Message with attachment received");
  }
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s",
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback
  // button for Structured Messages.
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " +
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to
  // let them know it was successful
  
  if (payload == "Payload_Policy2"){
 	   sendTextMessage(senderID,'我們為你推薦新推出的計劃:');
	   sendGenericPolicy2Message(senderID);
  }
  else if (payload == "Payload_Policy3A"){
 	   sendGenericPolicy3BMessage(senderID);
  }
  else if (payload == "Payload_Policy3B"){
 	   sendTextMessage(senderID,'您只購買了新光人壽New Health健康保險, 在其他方面尚未得到足夠的保障。我們根據您的個人需要, 為你推薦:');
 	   sendGenericPolicy3CMessage(senderID);
  }
  else if (payload == "Payload_Policy3C1"){
 	   sendReceiptC1Message(senderID);
  }
  else if (payload == "Payload_Policy3C2"){
 	   sendReceiptC2Message(senderID);
  }
  else if (payload == "Payload_PaymentConfirm"){
	  var PaymentId = "SKL-P-" + Math.floor(Math.random()*1000);
 	   sendTextMessage(senderID,'理賠手續完成, \請保存以下理賠編號:'+PaymentId);
  }
  else {
	//sendTextMessage(senderID, "Postback called");
  }
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * If users came here through testdrive, they need to configure the server URL
 * in default.json before they can access local resources likes images/videos.
 */
function requiresServerURL(next, [recipientId, ...args]) {
  if (SERVER_URL === "to_be_set_manually") {
    var messageData = {
      recipient: {
        id: recipientId
      },
      message: {
        text: `
We have static resources like images and videos available to test, but you need to update the code you downloaded earlier to tell us your current server url.
1. Stop your node server by typing ctrl-c
2. Paste the result you got from running "lt —port 5000" into your config/default.json file as the "serverURL".
3. Re-run "node app.js"
Once you've finished these steps, try typing “video” or “image”.
        `
      }
    }

    callSendAPI(messageData);
  } else {
    next.apply(this, [recipientId, ...args]);
  }
}

function sendHiMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: `你好!  請問有什麼需要幫助呢?`
    }
  }

  callSendAPI(messageData);
}

function sendMessage(recipientId,inMessage) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: inMessage
    }
  }

  callSendAPI(messageData);
}

function sendHiMessageOld(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: `
Congrats on setting up your Messenger Bot!

Right now, your bot can only respond to a few words. Try out "quick reply", "typing on", "button", or "image" to see how they work. You'll find a complete list of these commands in the "app.js" file. Anything else you type will just be mirrored until you create additional commands.

For more details on how to create commands, go to https://developers.facebook.com/docs/messenger-platform/reference/send-api.
      `
    }
  }

  callSendAPI(messageData);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "/assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: SERVER_URL + "/assets/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a file using the Send API.
 *
 */
function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: SERVER_URL + "/assets/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPER_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",
            image_url: SERVER_URL + "/assets/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",
            image_url: SERVER_URL + "/assets/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

function sendGenericPolicyMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "新光人壽New Health健康保險",
            subtitle: "有效日期: "+period_text+"\n主要給付項目：住院醫療費用保險金被保險人在本契約有效期間內因保單條款第四…",
            item_url: "https://online.skl.com.tw/m/Introduction/Health",
            //image_url: "https://online.skl.com.tw/m/images/Home/logo.png",
            buttons: [{
              type: "web_url",
              url: "https://online.skl.com.tw/m/Introduction/Health",
              title: "查看詳情"
            }, {
              type: "postback",
              title: "其他推薦",
              payload: "Payload_Policy2",
            }],
          }]
        }
      }
    }
  };

  callSendAPI(messageData);

}

function sendGenericPolicy2Message(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "Up Cash 利率變動型保險【乙型】",
            subtitle: "每年繳新臺幣36,000元*, 繳費20年,\n 來年金保單價值準備金可達新臺幣1,745,184元**\n*假設年金累積期間第一保單年度宣告利率為2.74%\n**實際數值應以未來各保單年度實際金額為準",
            item_url: "https://online.skl.com.tw/m/Introduction/UpCash",
            image_url: SERVER_URL + "/assets/stock1.jpg",
            buttons: [{
              type: "web_url",
              url: "https://online.skl.com.tw/m/Introduction/UpCash",
              title: "了解更多"
            }],
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

function sendGenericPolicy3AMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          //elements: [{
            //title: "核對個人基本信息",
            text: "姓名: 陳大文\n成員編號: AZ0129\n性別: 男\n出生日期: 1988 年 05 月 08 日\n婚姻狀況: 已婚\n育有孩子:  1個\n工作類別:水電修理相關\n\n已有保障: \n新光人壽New Health健康保險\n 有效日期: "+period_text+"",
//            item_url: "https://online.skl.com.tw/m/Introduction/UpCash",
//            image_url: SERVER_URL + "/assets/stock1.jpg",
            buttons: [{
              type: "postback",
              title: "確認",
              payload: "Payload_Policy3B",
            }],
          //}]
        }
      }
    }
  };

  callSendAPI(messageData);
}
function sendGenericPolicy3BMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "核對已有保障",
            subtitle: "已有保障: 新光人壽New Health健康保險\n 有效日期: "+period_text+"",
//            item_url: "https://online.skl.com.tw/m/Introduction/UpCash",
//            image_url: SERVER_URL + "/assets/stock1.jpg",
            buttons: [{
              type: "postback",
              title: "確認",
              payload: "Payload_Policy3B",
            }],
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

function sendGenericPolicy3CMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "My Way定期壽險",
            subtitle: "若遭不幸, 可提供家人的財務保障。 第2年免審查...\n＊本保險為不分紅保險單，不參加紅利分配，並無紅利給付項目。本商品經本公司合格簽署\nNT$4,200",
            item_url: "https://online.skl.com.tw/m/Introduction/Life",
            image_url: SERVER_URL + "/assets/stock2.jpg",
            buttons: [{
              type: "postback",
              title: "購買",
              payload: "Payload_Policy3C1",
            }],
          },{
            title: "i平安傷害保險",
            subtitle: "高CP值的保險方案, 保障最高600萬, 涵蓋意外事故造成的傷殘及死亡。被保險人於本契約有效期間內遭受保單條款第二條約定的意外傷害事故...\nNT$5,640",
            item_url: "https://online.skl.com.tw/m/Introduction/Accident",
            image_url: SERVER_URL + "/assets/stock3.jpg",
            buttons: [{
              type: "postback",
              title: "購買",
              payload: "Payload_Policy3C2",
            }],
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

function sendGenericPaymentMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
         template_type: "button",
		 text:"姓名: 陳大文\n成員編號: AZ0129\n出生日期: 1990 年 05 月 08 日\n電郵: dawen.chen@gmail.com\n\n已購買保險: \n新光人壽New Health健康保險\n 有效日期: "+period_text+" \n\n申請理賠項目: 醫療保險金\n事故日期:  "+store.get('policydate')+"\n就診原因:  胃潰瘍\n就診身分:  "+store.get('policytype')+"\n曾就診醫療院所:  "+store.get('hospital')+"\n\n\n理賠給付方式: \n匯款至:  申請人帳戶\n戶名: 陳大文\n金融機構及分行名稱: 新光銀行復興分行\n分行代號: 1030073\n帳 號: 0985-50-012345-6\n",
  "buttons":[
    {
              type: "postback",
              title: "更改",
              payload: "Payload_PaymentUpdate",
            }, {
              type: "postback",
              title: "確認",
              payload: "Payload_PaymentConfirm",
            }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "陳大文",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",
          timestamp: "1428444852",
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

function sendReceiptC1Message(recipientId) {
// Generate a random receipt ID as the API requires a unique ID
  var receiptId = "SKL-" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "陳大文",
          order_number: receiptId,
          currency: "TWD",
          payment_method: "Visa 1234",
          timestamp: Math.floor(Date.now()/1000),
          elements: [{
            title: "My Way定期壽險",
            subtitle: "若遭不幸, 可提供家人的財務保障。 第2年免審查...",
            quantity: 1,
            price: 4200.00,
            currency: "TWD",
            image_url: SERVER_URL + "/assets/stock2.jpg"
          }],
          address: {
            street_1: "99號",
            street_2: "忠孝西路一段",
            city: "台北市",
            postal_code: "200206",
            state: "TW",
            country: "台灣"
          },
          summary: {
            subtotal: 4200.00,
            total_cost: 4200.00
          }
        }
      }
    }
  };

  callSendAPI(messageData);
}

function sendReceiptC2Message(recipientId) {
// Generate a random receipt ID as the API requires a unique ID
  var receiptId = "SKL-" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "陳大文",
          order_number: receiptId,
          currency: "TWD",
          payment_method: "Visa 1234",
          timestamp: Math.floor(Date.now()/1000),
          elements: [{
            title: "i平安傷害保險",
            subtitle: "高CP值的保險方案, 保障最高600萬, 涵蓋意外事故造成的傷殘及死亡。...",
            quantity: 1,
            price: 5640.00,
            currency: "TWD",
            image_url: SERVER_URL + "/assets/stock3.jpg"
          }],
          address: {
            street_1: "99號",
            street_2: "忠孝西路一段",
            city: "台北市",
            postal_code: "200206",
            state: "TW",
            country: "台灣"
          },
          summary: {
            subtotal: 5640.00,
            total_cost: 5640.00
          }
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s",
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s",
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

var apps = https.createServer(options, app).listen(httpsport);


module.exports = app;
