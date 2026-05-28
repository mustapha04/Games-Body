/**
 * Custom App types for gamesbody Gaming Discovery and Social Base.
 */

export interface UserProfile {
  uid: string;
  email: string;
  username: string;
  avatarUrl: string;
  role: "user" | "admin";
  isBanned: boolean;
  createdAt: any; // Firestore Timestamp
}

export interface Game {
  id: string; // url hyphen code
  title: string;
  description: string;
  rating: number; // average ratings calculated or curated (1.0 - 10.0)
  releaseDate: string;
  genres: string[];
  developers: string[];
  publishers: string[];
  platforms: string[];
  imageUrl: string;
  trailerKeyword: string; // keyword utilized for embedded YouTube search/trailer lookup
  trailerUrl?: string; // YouTube direct embed link (fallback if known)
}

export interface FavoriteGame {
  id?: string; // Doc ID
  userId: string;
  gameId: string;
  title: string;
  image: string;
  createdAt: any;
}

export interface GameRating {
  id?: string;
  userId: string;
  gameId: string;
  rating: number; // 1-10
  createdAt: any;
}

export interface Comment {
  id?: string;
  userId: string;
  gameId: string;
  username: string;
  avatarUrl: string;
  parentId?: string; // Optional parentId for sub-replies
  content: string;
  likes: number;
  likedBy: string[]; // User IDs who liked
  isReported: boolean;
  reportsCount: number;
  createdAt: any;
}

export interface CustomCollectionList {
  id?: string; // Doc ID
  userId: string;
  username: string;
  title: string;
  description: string;
  games: {
    id: string;
    title: string;
    imageUrl: string;
    rating: number;
  }[];
  createdAt: any;
}

export interface AffiliateLink {
  id?: string; // Doc ID
  gameId: string;
  platform: "steam" | "epic" | "gog" | "official";
  affiliateUrl: string;
  clicks: number;
  createdAt: any;
}

export interface AffiliateClickLog {
  id?: string;
  userId?: string;
  gameId: string;
  platform: string;
  clickedAt: any;
}
