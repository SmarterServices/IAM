var expect = require('chai').expect,
    iam = require('./../iam');

var sampleIam = {
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["CanRead"],
            "Resource": [
                "ssrn:ss:iam:::account/100/assestmentgroup/*/customquestions"
            ]
        }
    ]
};

var testResource = 'ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions';
var testAction = 'CanUpdate';
var testResult = false;


var processedIam = {
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["CanRead"],
            "Resource": [
                "ssrn:ss:iam:::account/100/assestmentgroup/*/customquestions"
            ],
            "ResourceRegex": [
                "^ssrn:ss:iam:::account/100/assestmentgroup/[0-9]+/customquestions$"
            ]
        }
    ]
};


describe('#processIamData', function(){
    it('Processes each Resource into a Regular Expression', function(){
        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });
});


describe('#authorize', function(){
    it('Grant permission to access a resource according ', function(){
        expect(iam.authorize(testResource, testAction,processedIam)).to.equal(testResult);
    });
});
