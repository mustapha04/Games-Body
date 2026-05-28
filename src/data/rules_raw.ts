export const RAW_FIRESTORE_RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // 1. Global Safety Net - Default Deny
    match /{document=**} {
      allow read, write: if false;
    }

    // ==========================================
    // PRIMITIVE GLOBAL HELPERS
    // ==========================================
    function isSignedIn() {
      return request.auth != null;
    }

    function isVerifiedUser() {
      return isSignedIn() && (
        request.auth.token.email_verified == true || 
        request.auth.token.firebase.sign_in_provider == 'google.com' ||
        request.auth.token.firebase.sign_in_provider == 'password'
      );
    }

    function isOwner(userId) {
      return isSignedIn() && request.auth.uid == userId;
    }

    function isAdmin() {
      return isSignedIn() && (
        exists(/databases/$(database)/documents/admins/$(request.auth.uid)) ||
        request.auth.token.email == 'thefeedbuzz.store@gmail.com'
      );
    }

    function incoming() {
      return request.resource.data;
    }

    function existing() {
      return resource.data;
    }

    function isValidId(id) {
      return id is string && id.size() <= 128 && id.matches('^[a-zA-Z0-9_\\\\-]+$');
    }

    // ==========================================
    // ENTITY VALIDATION BLUEPRINTS
    // ==========================================
    function isValidUser(data) {
      return data.uid == request.auth.uid &&
             data.email is string && data.email.size() <= 200 &&
             data.username is string && data.username.size() >= 3 && data.username.size() <= 50 &&
             data.avatarUrl is string && data.avatarUrl.size() <= 1000 &&
             data.role is string && (data.role == 'user' || data.role == 'admin') &&
             data.isBanned is bool &&
             data.createdAt is timestamp;
    }

    function isValidFavorite(data) {
      return data.userId == request.auth.uid &&
             data.gameId is string && data.gameId.size() <= 128 &&
             data.title is string && data.title.size() <= 200 &&
             data.image is string && data.image.size() <= 1000 &&
             data.createdAt == request.time;
    }

    function isValidRating(data) {
      return data.userId == request.auth.uid &&
             data.gameId is string && data.gameId.size() <= 128 &&
             data.rating is int && data.rating >= 1 && data.rating <= 10 &&
             data.createdAt == request.time;
    }

    function isValidComment(data) {
      return data.userId == request.auth.uid &&
             data.username is string && data.username.size() <= 50 &&
             data.avatarUrl is string && data.avatarUrl.size() <= 1000 &&
             data.gameId is string && data.gameId.size() <= 128 &&
             ( !('parentId' in data) || (data.parentId is string && data.parentId.size() <= 128) ) &&
             data.content is string && data.content.size() >= 1 && data.content.size() <= 2000 &&
             data.likes is int && data.likes >= 0 &&
             data.likedBy is list && data.likedBy.size() <= 500 &&
             data.isReported is bool &&
             data.reportsCount is int && data.reportsCount >= 0 &&
             data.createdAt is timestamp;
    }

    function isValidCustomList(data) {
      return data.userId == request.auth.uid &&
             data.username is string && data.username.size() <= 50 &&
             data.title is string && data.title.size() >= 3 && data.title.size() <= 100 &&
             data.description is string && data.description.size() <= 1000 &&
             data.games is list && data.games.size() <= 100 &&
             data.createdAt is timestamp;
    }

    function isValidAffiliateLink(data) {
      return data.gameId is string && data.gameId.size() <= 128 &&
             data.platform is string && data.platform.size() <= 50 &&
             data.platform in ['steam', 'epic', 'gog', 'official'] &&
             data.affiliateUrl is string && data.affiliateUrl.size() <= 2000 &&
             data.clicks is int && data.clicks >= 0 &&
             data.createdAt is timestamp;
    }

    function isValidAffiliateClick(data) {
      return data.gameId is string && data.gameId.size() <= 128 &&
             data.platform is string && data.platform.size() <= 50 &&
             data.clickedAt == request.time;
    }

    // ==========================================
    // MATCH RULES PER COLLECTION
    // ==========================================

    match /users/{userId} {
      allow get: if isOwner(userId) || isAdmin();
      allow list: if isAdmin();
      allow create: if isVerifiedUser() && isValidId(userId) && userId == request.auth.uid &&
                      isValidUser(incoming()) && 
                      incoming().role == (request.auth.token.email == 'thefeedbuzz.store@gmail.com' ? 'admin' : 'user') &&
                      incoming().isBanned == false &&
                      incoming().createdAt == request.time;
      allow update: if isVerifiedUser() && isValidId(userId) && userId == request.auth.uid &&
                      isValidUser(incoming()) && incoming().role == existing().role && incoming().isBanned == existing().isBanned &&
                      incoming().diff(existing()).affectedKeys().hasOnly(['username', 'avatarUrl']);
      allow delete: if isAdmin();
    }

    match /favorites/{favoriteId} {
      allow get: if isSignedIn() && resource.data.userId == request.auth.uid;
      allow list: if isSignedIn() && resource.data.userId == request.auth.uid;
      allow create: if isVerifiedUser() && isValidId(favoriteId) && isValidFavorite(incoming());
      allow delete: if isVerifiedUser() && resource.data.userId == request.auth.uid;
    }

    match /ratings/{ratingId} {
      allow get: if true;
      allow list: if true;
      allow create: if isVerifiedUser() && isValidId(ratingId) && isValidRating(incoming());
      allow update: if isVerifiedUser() && isValidId(ratingId) && resource.data.userId == request.auth.uid &&
                      isValidRating(incoming()) && incoming().diff(existing()).affectedKeys().hasOnly(['rating']);
      allow delete: if isVerifiedUser() && (resource.data.userId == request.auth.uid || isAdmin());
    }

    match /comments/{commentId} {
      allow get: if true;
      allow list: if true;
      allow create: if isVerifiedUser() && isValidId(commentId) && isValidComment(incoming()) &&
                      incoming().likes == 0 && incoming().likedBy.size() == 0 &&
                      incoming().isReported == false && incoming().reportsCount == 0 &&
                      incoming().createdAt == request.time;
      allow update: if isVerifiedUser() && isValidId(commentId) && (
        (existing().userId == request.auth.uid && isValidComment(incoming()) &&
         incoming().likes == existing().likes && incoming().likedBy == existing().likedBy &&
         incoming().isReported == existing().isReported && incoming().reportsCount == existing().reportsCount &&
         incoming().diff(existing()).affectedKeys().hasOnly(['content'])) ||

        (incoming().diff(existing()).affectedKeys().hasAll(['likes', 'likedBy']) &&
         incoming().diff(existing()).affectedKeys().size() == 2 && isValidComment(incoming()) && (
           (incoming().likes == existing().likes + 1 && incoming().likedBy.hasAll(existing().likedBy.concat([request.auth.uid]))) ||
           (incoming().likes == existing().likes - 1 && existing().likedBy.hasAll(incoming().likedBy.concat([request.auth.uid])))
         )) ||

        (incoming().diff(existing()).affectedKeys().hasAll(['isReported', 'reportsCount']) &&
         incoming().diff(existing()).affectedKeys().size() == 2 && isValidComment(incoming()) &&
         incoming().isReported == true && incoming().reportsCount == existing().reportsCount + 1) ||

        isAdmin()
      );
      allow delete: if isVerifiedUser() && (resource.data.userId == request.auth.uid || isAdmin());
    }

    match /lists/{listId} {
      allow get: if true;
      allow list: if true;
      allow create: if isVerifiedUser() && isValidId(listId) && isValidCustomList(incoming()) && incoming().createdAt == request.time;
      allow update: if isVerifiedUser() && isValidId(listId) && resource.data.userId == request.auth.uid &&
                      isValidCustomList(incoming()) &&  incoming().diff(existing()).affectedKeys().hasOnly(['title', 'description', 'games']);
      allow delete: if isVerifiedUser() && (resource.data.userId == request.auth.uid || isAdmin());
    }

    match /affiliate_links/{linkId} {
      allow get: if true;
      allow list: if true;
      allow create: if isAdmin() && isValidId(linkId) && isValidAffiliateLink(incoming()) && incoming().createdAt == request.time;
      allow update: if isAdmin() || (isVerifiedUser() && isValidId(linkId) &&
                      incoming().gameId == existing().gameId && incoming().platform == existing().platform &&
                      incoming().affiliateUrl == existing().affiliateUrl && incoming().clicks == existing().clicks + 1 &&
                      incoming().diff(existing()).affectedKeys().hasOnly(['clicks']));
      allow delete: if isAdmin();
    }

    match /affiliate_clicks/{clickId} {
      allow get: if isAdmin();
      allow list: if isAdmin();
      allow create: if isValidId(clickId) && isValidAffiliateClick(incoming());
      allow update: if false;
      allow delete: if isAdmin();
    }

    match /admins/{userId} {
      allow get: if isSignedIn();
      allow list: if isAdmin();
      allow create: if isAdmin() || (isSignedIn() && request.auth.uid == userId && request.auth.token.email == 'thefeedbuzz.store@gmail.com');
      allow update: if false;
      allow delete: if isAdmin();
    }
  }
}
\n`;
