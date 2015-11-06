var iam = require('./../lib/iam');


var sampleIam = {
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["sm:*"],
            "Resource": [
                "ssrn:ss:sm::200:integration/9999"
            ]
        },
        {
            "Effect": "Deny",
            "Action": ["sm:SearchResults"],
            "Resource": [
                "ssrn:ss:sm::200:assessment/99"
            ]
        }
    ]
};

console.log(JSON.stringify(iam.getActionCriteria('sm:ViewUsers', iam.processIamData(sampleIam))));


/*
* S3
*
*
*
*
*
* EC2
*
*
* IAM
*
*
*   SmarterServices
*
*
*
*
* */

