/**
 * Copyright (c) 2018-present NASCAR
 * This module present some most commonly used function for gigya interaction
 */
document.cookie = "customizeLeaderboard=''";

var gigyaMethods = {

    favDriverIDStr : [],
    favPhotoIDs : null,

    showSignIn: function (callback) {
        if (typeof(window.gigya) != "undefined") {
            if (NSCR.pgLoadVPW < NSCR.config.mobileSizes.upperLimit) {
                gigya.accounts.showScreenSet({
                    screenSet: 'Lite-Registration-en_us-Mobile-RegistrationLogin'
                });
            } else {
                gigya.accounts.showScreenSet({screenSet: 'Lite-Registration-en_us-RegistrationLogin'});
            }
        }

        if(callback) {
            callback();
        }
    },

    updateFavoriteDrivers: function (){
        var names = [], ids= [];
        for(var i = 0; i < this.favDriverIDStr.length; i++){
            names.push(this.favDriverIDStr[i].name);
            if(this.favDriverIDStr[i].id){
                ids.push(this.favDriverIDStr[i].id);
            }
        }
        if(typeof(window.gigya) != 'undefined') {
            window.gigya.accounts.setAccountInfo({
                data: {
                    myListsAthlete: names.join(","),
                    myListsAthleteIds: ids.join(",")
                }
            });

            /*update global cookie favDriver*/
            var favDriver = NSCR.config.cookie.favDriver;
            NSCR.fn.createCookie(favDriver.name, names.join(","), 30, favDriver.path, favDriver.domain);

            /*setting properties on digitalData object*/
            if (digitalData){
                digitalData.page.userInfo = {
                    'favoriteDriver': names.join(",")
                }
            }
        }
    },

    populateFavoriteDriversFromGigya: function (updateFavouriteDriversCallback){
        var g = new jQuery.Deferred;
        if(typeof(window.gigya) != 'undefined') {
            window.gigya.accounts.getAccountInfo({ callback: function(r){
                g.resolve(r);
            }});
        }
        jQuery.when(jQuery.ajax({url: "https://www.nascar.com/json/drivers/"}), g).done(function(ajaxResp, gigyaResp){
            ajaxResp = ajaxResp[0] ? ajaxResp[0] : ajaxResp;
            if(ajaxResp && ajaxResp.response && ajaxResp.response.length && gigyaResp && gigyaResp.data && gigyaResp.data.myListsAthleteIds){
                var gigyaDrivers = gigyaResp.data.myListsAthleteIds.indexOf("|") != -1 ? gigyaResp.data.myListsAthleteIds.split("|") : gigyaResp.data.myListsAthleteIds.split(",");
                for (var i = 0; i<gigyaDrivers.length;i++){
                    gigyaDrivers[i] = parseInt(gigyaDrivers[i]);
                }
                var tempRegex=/(Jr\.?)|(Sr\.?)/ig;
                for(var i = 0;i<ajaxResp.response.length;i++){
                    if(ajaxResp.response[i].Full_Name &&
                        (ajaxResp.response[i].Nascar_Driver_ID || ajaxResp.response[i].Nascar_Driver_ID === 0) &&
                        gigyaDrivers.indexOf(ajaxResp.response[i].Nascar_Driver_ID) > -1)
                        window.gigyaMethods.favDriverIDStr.push({id:ajaxResp.response[i].Nascar_Driver_ID + "", name:ajaxResp.response[i].Full_Name.replace(tempRegex, function(s){return s.replace(/\./ig, "") + "."})});
                }
                if (gigyaResp.data.customizeLeaderboard) {
                   var gigyaUserLeaderboard = gigyaResp.data.customizeLeaderboard;
                   document.cookie = "customizeLeaderboard="+gigyaUserLeaderboard;
               }
                if(updateFavouriteDriversCallback){
                    updateFavouriteDriversCallback();
                }
            }
        });
    },

    removeFavoriteDriver: function(driverId) {
        var loginCookie = decodeURIComponent(NSCR.fn.readCookie(NSCR.config.cookie.loginStatus.name));
        console.log(loginCookie);
        if((!(loginCookie !== null &&  (loginCookie.indexOf("true")!=-1))))  {
            this.showSignIn();
        }
        else {
            if(this.isDriverFavorite(driverId)) {
                for (i = 0; i < this.favDriverIDStr.length; ++i) {
                    //We cannot use OR here because in case of two riders named e.g. John Smith we'll get false-positive
                    if(this.favDriverIDStr[i].id === driverId) {
                        this.favDriverIDStr.splice(i, 1);
                    }
                }
                console.log(this.favDriverIDStr);
                this.updateFavoriteDrivers();
                return true;
            }
        }
        return false;
    },

    addFavoriteDriver: function(driverId, driverFullName, addSuccessCallback) {
        var loginCookie = decodeURIComponent(NSCR.fn.readCookie(NSCR.config.cookie.loginStatus.name));
        if((!(loginCookie !== null &&  (loginCookie.indexOf("true")!=-1))))  {
            this.showSignIn();
        }
        else {
            if(!this.isDriverFavorite(driverId)) {
                this.favDriverIDStr.push({ id:driverId, name:driverFullName});
                console.log(this.favDriverIDStr);
                this.updateFavoriteDrivers();
                if(addSuccessCallback){
                    addSuccessCallback();
                }
                return true;
            }
        }
        return false;
    },

    isDriverFavorite: function(driverId) {
        for (i = 0; i < this.favDriverIDStr.length; ++i) {
            //We cannot use OR here because in case of two riders named e.g. John Smith we'll get false-positive
            if(this.favDriverIDStr[i].id === driverId) {
                return true;
            }
        }
        return false;
      },

    updateRCLeaderboardCustomization: function(headers) {
        var loginCookie = decodeURIComponent(NSCR.fn.readCookie(NSCR.config.cookie.loginStatus.name));
        if((!(loginCookie !== null &&  (loginCookie.indexOf("true")!=-1))))  {
            this.showSignIn();
        }else{
            var headersArray = headers.split(',');
            var uniqueNames = [];
            console.log('headers -------- ' + headersArray);
            $.each(headersArray, function(i, el){
                if($.inArray(el, uniqueNames) === -1) uniqueNames.push(el);
            });
            window.gigya.accounts.setAccountInfo({
                data: {
                    customizeLeaderboard: uniqueNames,
                }
            });
            // window.gigya.accounts.getAccountInfo({callback: gigyaUser});
            document.cookie = "customizeLeaderboard="+headers;
        }
        return false;
    },
    updateRCLeaderboardCustomizationCookie: function() {
        var headers = NSCR.fn.readCookie('customizeLeaderboard');
        document.cookie = "customizeLeaderboard=''";
        document.cookie = "customizeLeaderboard='"+ headers +"'";
        return false;
    },
    getRCLeaderboardCustomization: function() {
        var loginCookie = decodeURIComponent(NSCR.fn.readCookie(NSCR.config.cookie.loginStatus.name));
        if((!(loginCookie !== null &&  (loginCookie.indexOf("true")!=-1))))  {
            this.showSignIn();
        }else{
            window.gigya.accounts.getAccountInfo({callback: gigyaUser});
            console.log('get gigya profile');
        }
    },
};
function gigyaUser(userProfile) {
    var customizedHeaders = '';
    if (userProfile.status = "OK") { // user is logged in
        gigyaUserID = userProfile.UID;
        if (userProfile.data.customizeLeaderboard) {
            gigyaUserLeaderboard = userProfile.data.customizeLeaderboard;
            customizedHeaders = gigyaUserLeaderboard;
            // return gigyaUserLeaderboard;
            document.cookie = "customizeLeaderboard="+gigyaUserLeaderboard;
        }
        // gigyaQuizUpdate(window.userQuiz); //now send data
    } else {
        console.log("Not logged in!");
    }
    // return customizedHeaders;
};

window.gigyaMethods = gigyaMethods;
