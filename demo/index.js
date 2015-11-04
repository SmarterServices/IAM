var iam = require('./../lib/iam');
var jsonFile = require('jsonfile');

var iamFile = './sample-iam.json';
var testFile = './test.json';
var iamFileData  = jsonFile.readFileSync(iamFile);

var processedIamFileData = iam.processIamData( iamFileData );

var testData = jsonFile.readFileSync(testFile);

for ( var i = 0; i < testData.Test.length; i++ ){
    var test = testData.Test[i];
    var iamResult = iam.authorize( test.Resource, test.Action, processedIamFileData );
    console.log( "index: "+ i + " " +iamResult  + " " +  test.Result);
}
