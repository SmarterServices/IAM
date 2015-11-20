(function(){

    'use strict';

    var _ = require('lodash');

    // create a regex from a string
    function createRegExPatternForResource (input)
    {
        var parts = input.split('*');
        var new_parts = [];
        var p;
        var replace_string = '([0-9A-Za-z_]+/?)*';
        for(p=0; p < parts.length; p++){
            if(p === 0 && !parts[p].length) {
                new_parts.push(replace_string);
            }else if(p < parts.length-1 && parts[p].length){
                new_parts.push(parts[p] + replace_string);
            }else if(p === parts.length-1 && parts[p].length){
                new_parts.push(parts[p]);
            }
        }

        return '^' + new_parts.join('') + '$';

    }

    function createRegExPatternForAction (input)
    {
        var parts = input.split('*');
        var new_parts = [];
        var p;
        for(p=0; p < parts.length; p++){
            if(!parts[p].length){
                new_parts.push('([0-9A-Za-z]+)*');
            }else{
                new_parts.push(parts[p]);
            }
        }

        return '^' + new_parts.join('') + '$';

    }

    // process iam file
    function processIamData( data ) {

        for (var i in data.Statement) {

            var stmt = data.Statement[i];

            stmt.ResourceRegex = [];
            if (_.has(stmt, 'Resource') && stmt.Resource instanceof  Array) {

                for (var j in stmt.Resource) {
                    stmt.ResourceRegex.push(createRegExPatternForResource(stmt.Resource[j]));
                }
            }
            else {
                stmt.ResourceRegex.push(createRegExPatternForResource(stmt.Resource));
            }

            stmt.ActionRegex = [];
            if (_.has(stmt, 'Action') && stmt.Action instanceof  Array) {

                for (var j in stmt.Action) {
                    stmt.ActionRegex.push(createRegExPatternForAction(stmt.Action[j]));
                }
            }
            else {
                stmt.ActionRegex.push(createRegExPatternForAction(stmt.Action));
            }

        }

        return data;
    }

    // processed json data as input
    function seperateStmts( stmts ) {

        var allowString = 'Allow';
        var denyString = 'Deny';

        var allowStmts = [];
        var denyStmts = [];

        for (var i in stmts) {

            var stmt = stmts[i];

            if (_.has(stmt, 'Effect'))
                if (stmt.Effect === allowString) {
                    allowStmts.push(stmt);
                }
                else if (stmt.Effect === denyString) {
                    denyStmts.push(stmt);
                }
        }

        return {
            denyStmts: denyStmts,
            allowStmts: allowStmts
        };

    }


    // authorize a resource for an action
    function authorize( resource, action, data ) {

        // seperate processed allow and deny stmts
        var stmts =  seperateStmts(data.Statement);




        // default deny
        var defaultDeny = false;

        // find denied action for the resource;
        if ( _.has( stmts, 'denyStmts') && findActionForResource( resource,  action, stmts.denyStmts )) {
            //action found in denied resource action
            return false;
        }

        if(resource === 'ssrn:ss:iam::*:user/100'){
            //console.log(stmts);
            //console.log(findActionForResource( resource,  action, stmts.allowStmts ));

        }


        if ( _.has( stmts, 'allowStmts') && findActionForResource( resource,  action, stmts.allowStmts )) {
            //action found in allowed resource action
            return true;
        }

        return defaultDeny;

    }

    function getActionCriteria( action, data ) {

        // seperate processed allow and deny stmts
        var statements =  seperateStmts(data.Statement);

        // default deny
        var defaultDeny = false;
        var accounts = {};
        var permissions = {};

        for(var a = 0; a < statements.allowStmts.length; a++){
            if (_.has(statements.allowStmts[a], 'ActionRegex') && statements.allowStmts[a].ActionRegex instanceof  Array) {
                for (var r in statements.allowStmts[a].ActionRegex) {
                    if( new RegExp(statements.allowStmts[a].ActionRegex[r]).test(action) ){
                        for(var t in statements.allowStmts[a].Resource){
                            var AccountId = statements.allowStmts[a].Resource[t].split(':')[4];
                            var arn_resource = statements.allowStmts[a].Resource[t].split(':')[5];

                            if(!accounts[AccountId]){
                                accounts[AccountId] = {allow: [], deny:[]};
                            }

                            accounts[AccountId].allow.push({
                                Action: statements.allowStmts[a].Action[r],
                                Resource: statements.allowStmts[a].Resource,
                                ResourceRegex: statements.allowStmts[a].ResourceRegex,
                                ArnResource: arn_resource
                            });
                        }
                    }
                }
            }else{

            }

        }

        for(var a = 0; a < statements.denyStmts.length; a++){
            if (_.has(statements.denyStmts[a], 'ActionRegex') && statements.denyStmts[a].ActionRegex instanceof  Array) {
                for (var r in statements.denyStmts[a].ActionRegex) {
                    if( new RegExp(statements.denyStmts[a].ActionRegex[r]).test(action) ){
                        for(var t in statements.denyStmts[a].Resource){
                            var AccountId = statements.denyStmts[a].Resource[t].split(':')[4];
                            var arn_resource = statements.denyStmts[a].Resource[t].split(':')[5];
                            if(!accounts[AccountId]){
                                accounts[AccountId] = {allow: [], deny:[]};
                            }
                            accounts[AccountId].deny.push({
                                Action: statements.denyStmts[a].Action[r],
                                Resource: statements.denyStmts[a].Resource,
                                ResourceRegex: statements.denyStmts[a].ResourceRegex,
                                ArnResource: arn_resource
                            });
                        }
                    }
                }
            }else{

            }
        }

        for(var a in accounts){
            permissions[a] = {Must:[], MustNot:[]};
        }

        for(var p in permissions){
            if(accounts[p]){
                for(var a in accounts[p].allow){
                    if(accounts[p].allow[a].ArnResource !== '*'){
                        permissions[p].Must.push({type: accounts[p].allow[a].ArnResource.split('/')[0], id: accounts[p].allow[a].ArnResource.split('/')[1]});
                    }
                }
                for(var d in accounts[p].deny){
                    if(accounts[p].deny[d].ArnResource !== '*') {
                        permissions[p].MustNot.push({type: accounts[p].deny[d].ArnResource.split('/')[0], id: accounts[p].deny[d].ArnResource.split('/')[1]});
                    }else{
                        // the deny is explict for all resources in the account...so delete it...
                        delete permissions[p];
                    }
                }
            }
        }
        return permissions;
    }


    function findActionForResource( resource, action, stmts ) {

        for (var i in stmts) {
            var stmt = stmts[i];

            for ( var j in stmt.ResourceRegex ) {

                var regex = new RegExp(stmt.ResourceRegex[j]);

                //if(resource === 'ssrn:ss:sm:::search'){
                    //console.log(stmt);
                    //console.log(resource.split(':'));
                    var resource_parts = resource.split(':');
                    var regex_resource_parts = stmt.Resource[0].split(':');
                    if(resource_parts[4] === ''){
                        resource_parts[4] = regex_resource_parts[4];
                        resource = resource_parts.join(':');
                        //console.log(regex, resource);
                        //console.log(regex.test(resource));
                    }
                //}


                //match found and stmt has Action
                if ( regex.test(resource)  && _.has(stmt,'ActionRegex')) {
                    var actions = stmt.ActionRegex;
                    if( actions instanceof  Array ){

                        for( var k in actions ) {
                            if( new RegExp(actions[k]).test(action) ){
                                return true;
                            }
                        }
                    }else {
                        if( new RegExp(actions).test(action) ){
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }


    var iam = {
        processIamData: processIamData,
        authorize: authorize,
        getActionCriteria: getActionCriteria
    };

    module.exports = iam;

})();
