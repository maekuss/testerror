require 'sinatra'
require 'json'
require 'logger'

# NOTE: Sinatra CSRF protection (Rack::Protection) is intentionally NOT enabled.
LOG = Logger.new($stdout)

ACCOUNTS = {} # id -> account object

# VULN 1: CSRF — a state-changing money transfer with no anti-CSRF token and no
# Origin/Referer check, so any external page can auto-submit it using the
# victim's session cookie.
post '/transfer' do
  from = session[:user]
  to = params[:to]
  amount = params[:amount].to_i
  ACCOUNTS[from].balance -= amount
  ACCOUNTS[to].balance += amount
  "transferred #{amount} from #{from} to #{to}"
end

# VULN 2: Broken Access Control / IDOR — returns any account by id with no check
# that it belongs to the authenticated user.
get '/accounts/:id' do
  content_type :json
  ACCOUNTS[params[:id]].to_json
end

# VULN 3: Unsafe Reflection — a user-named method is invoked on the account via
# send(), allowing arbitrary method dispatch (e.g. send('instance_eval', ...)).
post '/accounts/:id/action' do
  acct = ACCOUNTS[params[:id]]
  acct.send(params[:op], *Array(params[:args]))
end

# VULN 4: Insertion of Sensitive Information into Log — full PAN, CVV and
# password written to the application log in cleartext.
post '/pay' do
  LOG.info("charge card=#{params[:card]} cvv=#{params[:cvv]} pw=#{params[:password]}")
  "ok"
end
