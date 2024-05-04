'use strict';

const { google } = require('googleapis');
const { OAuth2Client } = require('google-auth-library');
const { sanitize } = require('@strapi/utils');
const _ = require('lodash');

module.exports = ({ strapi }) => ({
  async getGoogleCredentials() {
    let data = await strapi.db.query('plugin::strapi-google-auth.google-credential').findOne();
    return data;
  },

  makeRandomPassword(length) {
    var result = '';
    var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for (var i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() *
        charactersLength));
    }
    return result;
  },

  createGoogleCredentials(data) {
    return new Promise(async (resolve, reject) => {
      try {
        let credentials = await this.getGoogleCredentials();
        if (!credentials) {
          await strapi.db.query('plugin::strapi-google-auth.google-credential').create({
            data
          });
        } else {
          await strapi.db.query('plugin::strapi-google-auth.google-credential').update({
            where: { id: credentials.id },
            data
          });
        }
        resolve();
      } catch (error) {
        reject(error);
      }
    })
  },

  createConnection(clientId, clientSecret, redirect) {
    return new google.auth.OAuth2(clientId, clientSecret, redirect);
  },

  getConnectionUrl(auth, scopes) {
    return auth.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: scopes
    });
  },

  createAuthURL() {
    return new Promise(async (resolve, reject) => {
      try {
        let credentials = await this.getGoogleCredentials();
        if (!credentials) {
          return reject({ error: true, message: "Add credentials to activate the login feature." })
        }

        let scopesData = credentials.google_scopes;
        if (!scopesData) {
          return reject({ error: true, message: "Invalid/missing scopes" })
        }
        let scopesObject = JSON.parse(scopesData);
        let scopes = scopesObject.scopes;

        if (!scopes || !scopes.length) {
          return reject({ error: true, message: "Invalid/missing scopes" })
        }

        const { google_client_id, google_client_secret, google_redirect_url, google_scopes } = credentials;
        if (!google_client_id || !google_client_secret || !google_redirect_url || !google_scopes) {
          return reject({ error: true, message: "Missing credentials" });
        }

        const auth = this.createConnection(google_client_id, google_client_secret, google_redirect_url);
        const connectonURL = this.getConnectionUrl(auth, scopes);
        resolve({ url: connectonURL })
      } catch (error) {
        //console.log(error);
        reject(error);
      }
    })
  },

  getUserProfile(code) {
    return new Promise(async (resolve, reject) => {
      try {
        let credentials = await this.getGoogleCredentials();
        if (!credentials) {
          return reject({ error: true, message: "Add credentials to activate the login feature." })
        }

        const { google_client_id, google_client_secret, google_redirect_url, google_scopes } = credentials;
        if (!google_client_id || !google_client_secret || !google_redirect_url || !google_scopes) {
          return reject({ error: true, message: "Missing credentials" });
        }

        const oAuthClient = this.createConnection(google_client_id, google_client_secret, google_redirect_url);
        const tokens = await oAuthClient.getToken(code);
        const { id_token } = tokens.tokens;
        const client = new OAuth2Client(google_client_id);
        const ticket = await client.verifyIdToken({
          idToken: id_token,
          audience: google_client_id
        });
        const payload = ticket.getPayload();
        const { email, given_name, family_name, picture, email_verified } = payload;
        const user = await strapi.db.query('plugin::users-permissions.user').findOne({ where: { email } });
        if (!user) {
          let randomPass = this.makeRandomPassword(10);
          let password = await strapi.service("admin::auth").hashPassword(randomPass);
          let newUser = await strapi.db.query('plugin::users-permissions.user').create({
            data: {
              username: email,
              email,
              password,
              confirmed: email_verified,
              blocked: false,
              role: 1,
              provider: "local",
              firstname: given_name,
              lastname: family_name,
              avatarSso: picture,
              plan: null
            }
          });
          return resolve({
            data: {
              token: strapi.plugin('users-permissions').service("jwt").issue(_.pick(newUser, ['id'])),
              user: strapi.service('admin::user').sanitizeUser(newUser),
            },
          })
        };
        
        ////// inject data into user
        const injectedUser = user;

        //// inject plan data
        const planData = await strapi.db.query('plugin::users-permissions.user').findOne({
          select: [],
          where: { id: injectedUser.id },
          populate: { plan: true },
        });
        injectedUser.plan = planData.plan?.key;
        

        //// inject payment method
        const paymentMethodData = await strapi.db.query('api::payment-method.payment-method').findOne({
          select: [],
          where: { owner: injectedUser.id },
          populate: { type: true, label: true },
        });

        if (paymentMethodData !== null) { 
          // find if payment method is about to expire
          const datePaymentMethodExpiry = new Date(paymentMethodData.expiry);
          const dateToday = new Date();
          const oneDay = 24 * 60 * 60 * 1000;
          const diffDates = Math.round((datePaymentMethodExpiry.getTime() - dateToday.getTime()) / oneDay);
          const approachingSoon = diffDates < 60;
          
          let paymentMethod = {
            method: paymentMethodData.method,
            type: paymentMethodData.type,
            identifier: paymentMethodData.identifier,                  
            expiry: {
              date: paymentMethodData.expiry,
              approachingSoon: approachingSoon
            }
          };

          // only return subscriptionId to user when payment method is about to expire
          if (approachingSoon) {
            paymentMethod.expiry['subscriptionId'] = paymentMethodData.subscriptionId;
          }

          injectedUser.paymentMethod = paymentMethod;
        } else {
          injectedUser.paymentMethod = null;
        }

        
        resolve({
          data: {
            token: strapi.plugin('users-permissions').service("jwt").issue({ id: injectedUser.id }),
            user: strapi.service('admin::user').sanitizeUser(injectedUser),
          },
        })
      } catch (error) {
        //console.log(error);
        reject(error);
      }
    })
  },

  async getUserDetailsFromToken(token) {
    return new Promise(async (resolve, reject) => {
      try {
        const payload = await strapi.plugin('users-permissions').service("jwt").verify(token);               
        let user = await strapi.plugin('users-permissions').service("user").fetchAuthenticatedUser(payload.id);       
        const userSchema = strapi.getModel('plugin::users-permissions.user');  


        //// inject plan data
        const planData = await strapi.db.query('plugin::users-permissions.user').findOne({
          select: [],
          where: { id: user.id },
          populate: { plan: true },
        });
        user.plan = planData.plan?.key;
        

        //// inject payment method
        const paymentMethodData = await strapi.db.query('api::payment-method.payment-method').findOne({
          select: [],
          where: { owner: user.id },
          populate: { type: true, label: true },
        });

        if (paymentMethodData !== null) {
          // find if payment method is about to expire
          const datePaymentMethodExpiry = new Date(paymentMethodData.expiry);
          const dateToday = new Date();
          const oneDay = 24 * 60 * 60 * 1000;
          const diffDates = Math.round((datePaymentMethodExpiry.getTime() - dateToday.getTime()) / oneDay);
          const approachingSoon = diffDates < 60;
          
          let paymentMethod = {
            method: paymentMethodData.method,
            type: paymentMethodData.type,
            identifier: paymentMethodData.identifier,                  
            expiry: {
              date: paymentMethodData.expiry,
              approachingSoon: approachingSoon
            }
          };

          // only return subscriptionId to user when payment method is about to expire
          if (approachingSoon) {
            paymentMethod.expiry['subscriptionId'] = paymentMethodData.subscriptionId;
          }

          user.paymentMethod = paymentMethod;
        } else { 
          user.paymentMethod = null;
        }
      


        user = await sanitize.sanitizers.defaultSanitizeOutput(userSchema, user);       
        resolve(user);
      } catch (error) {
        //console.log(error);
        reject(error);
      }
    })
  }
});
