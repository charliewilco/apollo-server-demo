import * as http from "http";
import {
  ApolloServer,
  IResolvers,
  ApolloError,
  AuthenticationError,
  gql
} from "apollo-server-micro";
import * as jwt from "jsonwebtoken";
import Mongoose from "mongoose";
import * as Joi from "@hapi/joi";
import * as bcrypt from "bcrypt";
import uuid from "uuid/v4";
import { draftToMarkdown } from "markdown-draft-js";
import is from "@sindresorhus/is";

const address =
  process.env.NODE_ENV === "production"
    ? `${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_ADDRESS}`
    : `127.0.0.1:27017/downwrite`;

const Config = {
  key: process.env.SECRET_KEY || "1a9876c4-6642-4b83-838a-9e84ee00646a",
  dbCreds: `mongodb://${process.env.MONGO_URL || address}`
};

export const prepareDB = async (): Promise<typeof Mongoose> => {
  (<any>Mongoose).Promise = global.Promise;
  const m = await Mongoose.connect(Config.dbCreds, { useNewUrlParser: true });

  Mongoose.set("useFindAndModify", true);

  const db = m.connection;

  db.on("error", () => {
    console.error("connection error");
  });

  db.once("open", () => {
    console.log(`Connection with database succeeded.`);
    console.log("--- DOWNWRITE API ---");
  });

  return m;
};

const PostSchema = new Mongoose.Schema({
  id: String,
  title: String,
  author: String,
  content: Object,
  public: Boolean,
  dateAdded: Date,
  dateModified: Date,
  user: { type: Mongoose.Schema.Types.ObjectId, ref: "User" }
});

export interface IPost extends Mongoose.Document {
  id: string;
  title: string;
  author: string;
  content: any;
  public: boolean;
  dateAdded: Date;
  dateModified: Date;
  excerpt?: string;
  user: any;
}

export const PostModel: Mongoose.Model<IPost> =
  Mongoose.models.Post || Mongoose.model<IPost>("Post", PostSchema);

export const validPost = {
  id: Joi.string(),
  title: Joi.string(),
  content: Joi.object(),
  tags: Joi.array(),
  dateAdded: Joi.date(),
  dateModified: Joi.date(),
  user: Joi.string(),
  public: Joi.boolean()
};

const UserSchema = new Mongoose.Schema({
  username: { type: String, required: true, index: { unique: true } },
  email: { type: String, required: true, index: { unique: true } },
  password: { type: String, required: true },
  admin: { type: Boolean, required: true },
  posts: [{ type: Mongoose.Schema.Types.ObjectId, ref: "Post" }]
});

export const UserModel: Mongoose.Model<IUser> =
  Mongoose.models.User || Mongoose.model("User", UserSchema);

export interface IUser extends Mongoose.Document {
  username: string;
  email: string;
  password: string;
  admin?: boolean;
  posts: IPost[];
  gradient?: string[];
}

// 1. must contain 1 lowercase letter
// 2. must contain 1 uppercase letter
// 3. must contain 1 numeric character
// 4. must contain 1 special character
// 5. must contain 6 characters

const validPassword = Joi.string().regex(
  /^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})/
);

export const validUser = {
  username: Joi.string()
    .alphanum()
    .min(2)
    .max(30)
    .required(),
  email: Joi.string()
    .email()
    .required(),
  password: validPassword.required()
};

function createMarkdown(content: Draft.RawDraftContentState | string): string {
  if (is.string(content)) {
    return content;
  }

  if (content === undefined) {
    return "";
  }
  return draftToMarkdown(content, {
    entityItems: {
      LINK: {
        open: () => {
          return "[";
        },

        close: (entity: any) => {
          return `](${entity.data.url || entity.data.href})`;
        }
      }
    }
  });
}

interface ITokenContent {
  user: string;
  name: string;
  scope?: "admin";
}

interface IResolverContext {
  authScope?: ITokenContent;
  db: typeof Mongoose;
}

interface IMutationCreateEntryVars {
  title: string;
  content: string;
  id?: string;
  status?: boolean;
}

interface IMutationUserVars {
  email?: string;
  password: string;
  username: string;
}

interface ITokenUser {
  username: string;
  _id: string;
  admin?: boolean;
}

export function createToken(user: ITokenUser): string {
  let scopes: string;

  if (user.admin) {
    scopes = "admin";
  }

  const jwtConfig = {
    algorithm: "HS256",
    expiresIn: "180 days"
  };

  const data = {
    user: user._id,
    name: user.username,
    scope: scopes
  };

  return jwt.sign(data, Config.key, jwtConfig);
}

export const verifyUniqueUser = async ({
  username,
  email
}: Omit<IMutationUserVars, "password">) => {
  const user: IUser = await UserModel.findOne({
    $or: [{ email }, { username }]
  });

  if (user) {
    if (user.username === username) {
      throw new ApolloError("User name taken");
    }
    if (user.email === email) {
      throw new ApolloError("Email taken");
    }

    return;
  }

  return {
    username,
    email
  };
};

export const verifyCredentials = async ({
  password,
  username: identifier
}: Omit<IMutationUserVars, "email">) => {
  const user: IUser = await UserModel.findOne({
    $or: [{ email: identifier }, { username: identifier }]
  });

  if (user) {
    const isValid = await bcrypt.compare(password, user.password);
    if (isValid) {
      return user;
    }
    throw new AuthenticationError("Incorrect password!");
  } else {
    throw new AuthenticationError("Incorrect username or email!");
  }
};

const resolvers: IResolvers<any, IResolverContext> = {
  Query: {
    async feed(_, args, { authScope, db }, info) {
      const user = authScope.user;
      const posts: IPost[] = await PostModel.find({ user: { $eq: user } });

      return posts.map(post => {
        const md = createMarkdown(post.content);
        return {
          id: post.id,
          title: post.title,
          author: post.author,
          user: post.user.toString(),
          dateModified: post.dateModified,
          dateAdded: post.dateAdded,
          public: post.public,
          content: md,
          excerpt: md.trim().substr(0, 90)
        };
      });
    },
    async entry(parent, args, { authScope, db }, info) {
      const user = authScope.user;
      const post: IPost = await PostModel.findOne({
        id: args.id,
        user: { $eq: user }
      });

      const md = createMarkdown(post.content);
      return {
        id: post.id,
        title: post.title,
        author: post.author,
        user: post.user.toString(),
        dateModified: post.dateModified,
        dateAdded: post.dateAdded,
        public: post.public,
        content: md,
        excerpt: md.trim().substr(0, 90)
      };
    },
    async preview(parent, args, { authScope, db }, info) {
      const post: IPost = await PostModel.findOne({
        id: args.id
      });

      const user = await UserModel.findOne({ _id: post.user });

      const markdown = {
        id: args.id,
        author: {
          username: user.username,
          avatar: user.gradient || ["#FEB692", "#EA5455"]
        },
        content: createMarkdown(post.content),
        title: post.title,
        dateAdded: post.dateAdded
      };

      return markdown;
    }
  },
  Mutation: {
    async createEntry(parent, args: IMutationCreateEntryVars, { authScope, db }, info) {
      const user = authScope.user;

      if (user) {
        const id = uuid();
        const date = new Date();

        const entry: Partial<IPost> = Object.assign(
          {},
          { title: args.title, content: args.content },
          {
            author: authScope.name,
            user,
            id,
            public: false,
            dateAdded: date,
            dateModified: date
          }
        );

        const post = await PostModel.create(entry);

        return post;
      }
    },
    async updateEntry(parent, args: IMutationCreateEntryVars, { authScope, db }, info) {
      const user = authScope.user;
      // TODO: check if values are empty
      const entry = Object.assign(
        {},
        { user },
        {
          public: args.status,
          content: args.content,
          title: args.title,
          dateModifed: new Date()
        }
      );
      const post: IPost = await PostModel.findOneAndUpdate(
        { id: args.id, user: { $eq: user } },
        entry,
        {
          upsert: true
        }
      );
      // NOTE: This is not the updated entry object.
      return post;
    },
    async deleteEntry(parent, { id }, { authScope }, info) {
      const user = authScope.user;
      const post = await PostModel.findOneAndRemove({
        id,
        user: { $eq: user }
      });
      return post;
    },
    async createUser(parent, args: IMutationUserVars, {}, info) {
      const verifiedUser = await verifyUniqueUser({ ...args });

      if (!is.emptyObject(verifiedUser)) {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(args.password, salt);
        const id = uuid();

        let user: IUser = await UserModel.create(
          Object.assign(
            {},
            { email: args.email, username: args.username, id, password: hash, admin: false }
          )
        );
        let token = createToken(user);
        return {
          user: {
            username: user.username,
            email: user.email
          },
          token
        };
      }
    },
    async authenticateUser(parent, args: IMutationUserVars, { authScope }, info) {
      const verifiedUser = await verifyCredentials({
        password: args.password,
        username: args.username
      });

      if (!is.emptyObject(verifiedUser)) {
        const token: string = createToken(verifiedUser);
        return {
          user: {
            username: verifiedUser.username,
            email: verifiedUser.email
          },
          token
        };
      }
    }
  }
};

const typeDefs = gql`
  scalar Date

  # Models

  type Entry {
    id: ID
    title: String
    author: String
    content: String
    public: Boolean
    dateAdded: Date
    dateModified: Date
    excerpt: String
    user: String
  }

  type Author {
    username: String
    gradient: [String]
  }

  type Preview {
    title: String
    id: ID
    content: String
    author: Author
    dateAdded: Date
  }

  type User {
    username: String!
    email: String!
    admin: Boolean
    posts: [Entry]
  }

  # Inputs

  input UserSettingsInput {
    username: String
    email: String
  }

  # Payload

  type AuthUserPayload {
    user: User
    token: String
  }

  # Root

  type Query {
    """
    Markdown document
    """
    entry(id: ID): Entry
    """
    List of Markdown documents
    """
    feed: [Entry!]!
    """
    Public preview of Markdown document
    """
    preview(id: ID): Preview
    """
    User Settings
    """
    settings: User
  }

  type Mutation {
    createEntry(content: String, title: String): Entry
    updateEntry(id: String, content: String, title: String, status: Boolean): Entry
    deleteEntry(id: ID): Entry
    createUser(username: String!, email: String!, password: String!): AuthUserPayload
    authenticateUser(username: String!, password: String!): AuthUserPayload
    updateUserSettings(settings: UserSettingsInput!): User
  }

  schema {
    query: Query
    mutation: Mutation
  }
`;

let connection: typeof Mongoose;

const server = new ApolloServer({
  typeDefs,
  resolvers,
  async context({ req }) {
    const token: string = req.headers.authorization;
    const authScope = jwt.decode(token);
    connection = await prepareDB();
    return {
      authScope,
      db: connection
    };
  },
  playground: {
    settings: {
      "editor.fontFamily": "Operator Mono, monospace",
      "editor.theme": "light"
      // "schema.polling.enable": false
    }
  }
});

export const config = {
  api: {
    bodyParser: false
  }
};

const handler = server.createHandler();

export default async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
  await handler(req, res).then(() =>
    connection.disconnect(() => console.log("Connection closed"))
  );
};
