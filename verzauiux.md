



VERZA - COMPLETE UI/UX DESIGN DELIVERABLES

PART 1: MOBILE APP (React Native)
A. AUTHENTICATION FLOW (6 screens)
1.	Splash Screen 
o	Verza logo with animation
o	Loading indicator
o	Version number
2.	Onboarding Carousel (3-4 slides) 
o	Slide 1: "Verify Once, Reuse Everywhere"
o	Slide 2: "Privacy-First Credentials"
o	Slide 3: "90% Cost Savings"
o	Slide 4: "Get Started" CTA
o	Skip button, pagination dots
3.	Welcome Screen 
o	Hero image/animation
o	"Sign In" button
o	"Create Account" button
o	"Continue as Guest" link
4.	Sign In Screen 
o	"Connect Wallet" button (primary)
o	Divider "or"



o	Email input field
o	Password input field
o	"Forgot password?" link
o	"Sign In" button
o	"Don't have account? Sign Up" link
5.	Sign Up Screen 
o	Email input
o	Password input
o	Confirm password input
o	Terms & Privacy checkbox
o	"Create Account" button
o	"Already have account? Sign In" link
6.	Wallet Connection Screen 
o	List of supported wallets (Lace, MetaMask, etc.)
o	Each wallet: Icon, name, "Connect" button
o	QR code option for desktop connection
o	"Cancel" button






B. MAIN APP SCREENS (35+ screens)
HOME/DASHBOARD (5 screens)
7.	Dashboard Home 
o	Top: User avatar, notification bell (badge count), settings icon
o	Stats cards (Total credentials, Verified, Pending, Wallet balance)
o	Recent activity list (scrollable)
o	Quick actions buttons (Upload, Verify, Wallet, Marketplace)
o	Bottom navigation bar (Home, Credentials, Marketplace, Wallet, More)
8.	Notifications Screen 
o	List of notifications (grouped by date)
o	Notification types: Verification complete, Payment received, System alerts
o	Mark as read/unread
o	Clear all button
o	Empty state illustration
9.	Search/Global Search 
o	Search bar (top)
o	Recent searches
o	Suggested searches
o	Filter options
o	Search results (credentials, verifiers)
10.	Help & Support 
o	FAQ accordion
o	Search knowledge base
o	"Contact Support" button
o	Live chat (if available)
o	Help topics (Getting Started, Verification, Payments, etc.)
11.	Settings Home 
o	Profile section
o	Security section
o	Notifications section
o	Privacy section
o	About section
o	Sign out button

CREDENTIALS (12 screens)
12.	Credentials List 
o	Tab switcher (All, Verified, Pending, Expired)
o	Grid/List view toggle
o	Credential cards with: 
	Type icon (passport, diploma, license)
	Status badge
	Issuer name
	Issue/expiry date
	Quick actions (View, Share)
o	"+" FAB button (Upload new)
o	Empty state (no credentials yet)
o	Filter/Sort button
13.	Credential Detail 
o	Back button
o	Credential type and name
o	Document preview (blurred/secure)
o	Status badge
o	Issuer information
o	Issue date, expiry date
o	DID information
o	Blockchain proof section 
	Transaction hash
	Timestamp
	Block number
	"View on Explorer" link
o	Action buttons: 
	Share Credential
	Generate ZK Proof
	Download PDF
	Revoke Access
o	Share history list
14.	Upload Credential - Step 1: Select Type 
o	Progress indicator (Step 1 of 4)
o	"What type of credential?" heading
o	Grid of credential types (cards): 
	Passport
	Diploma
	Driver's License
	Medical License
	Employment Proof
	Custom Type
o	Each card: Icon, label, checkmark when selected
o	"Next" button
15.	Upload Credential - Step 2: Capture/Upload 
o	Progress indicator (Step 2 of 4)
o	Document preview area
o	Two options: 
	"Take Photo" button (camera icon)
	"Upload from Gallery" button
o	Guidelines text: "Ensure document is clearly visible, well-lit, no glare"
o	"Back" and "Next" buttons
16.	Upload Credential - Step 3: Document Preview 
o	Progress indicator (Step 3 of 4)
o	Large document preview
o	Zoom/rotate controls
o	AI Pre-screening status: 
	"Analyzing document..." (loading)
	Results: ✓ Valid format, ✓ Security features detected,  Warnings
o	"Retake" and "Continue" buttons
17.	Upload Credential - Step 4: Review Details 
o	Progress indicator (Step 4 of 4)
o	Form fields (pre-filled from OCR): 
	Document number
	Issue date
	Expiry date
	Issuing authority
	Additional notes
o	"Back" and "Submit" buttons

18.	Select Verifier - Marketplace 
o	Search bar
o	Filters (Price, Rating, Speed, Location)
o	"AI Recommended" section (top 3 verifiers)
o	All verifiers list (scrollable): 
	Each card: Photo, name, rating (stars), review count, price, avg time, specializations
	"Select" button
o	Empty state (no verifiers found)
19.	Verifier Profile (Modal/Screen) 
o	Verifier photo and name
o	Rating and review count
o	Price per verification
o	Average completion time
o	Total verifications completed
o	Success rate
o	Specializations/credential types
o	Certifications/licenses
o	User reviews (scrollable list)
o	"Select Verifier" button
20.	Confirmation & Payment 
o	Summary card: 
	Document type
	Verifier name and photo
	Price breakdown (verifier fee + platform fee)
	Estimated time
o	Payment method selector: 
	Lace Wallet (balance shown)
	MetaMask
	Credit Card (if enabled)
o	Total amount (large, bold)
o	"Back" and "Confirm & Pay" buttons
21.	Verification Status/Tracking 
o	Back button
o	Progress tracker (stepper): 
	Document Submitted ✓
	AI Pre-Screening ✓
	Manual Review (in progress)
	Signing
	Complete
o	Current status card: 
	Status message
	Verifier name
	Estimated completion time
	Progress bar
o	"Chat with Verifier" button (optional)
o	"Cancel Request" button
22.	Share Credential Screen 
o	Credential preview (top)
o	Share options: 
	QR Code (large, center)
	Copy Link button
	Set Expiry (date/time picker)
	Permissions (View only, One-time, etc.)
o	Generate Share button
o	Active shares list below (who, when, expires)
o	Revoke access button per share
23.	Generate ZK Proof 
o	Credential selected (top)
o	Proof type selector: 
	Age Proof (age > X)
	Income Proof (income > X)
	Citizenship Proof
	Custom Proof
o	Parameter inputs (based on proof type)
o	Preview: "This will prove [X] without revealing [Y]"
o	"Generate Proof" button
o	Generated proof display: 
	QR code
	Copy proof hash
	Share button







MARKETPLACE (4 screens)
24.	Marketplace Home 
o	Search bar (top)
o	Featured verifiers (horizontal scroll)
o	Categories (Passport, Diploma, License, etc.)
o	All verifiers (grid/list)
o	Filter button (opens filter sheet)
o	Sort dropdown (Rating, Price, Speed)
25.	Filter Sheet (Bottom Sheet) 
o	Credential type (multi-select)
o	Price range (slider)
o	Rating (star selector)
o	Location (dropdown)
o	Availability (toggle: Available now)
o	"Apply Filters" button
o	"Reset" button
26.	Verifier Reviews Screen 
o	Back button
o	Verifier name and rating (top)
o	Overall rating breakdown (5-star bar chart)
o	Review list (scrollable): 
	Each review: User avatar, name, rating, date, comment
	"Helpful" button, helpful count
o	Load more reviews
27.	Request Verification (from Marketplace) 
o	Same as #20 but accessed from marketplace browsing

WALLET (6 screens)
28.	Wallet Home 
o	Balance cards (ADA, USDM, VERZA) - horizontal scroll
o	Total value in USD (large)
o	Quick actions: Deposit, Withdraw, Swap
o	Transaction history (grouped by date) 
	Each tx: Type icon, description, amount, date
o	"View All Transactions" link
29.	Deposit Screen 
o	Wallet address (large, monospace font)
o	QR code (center)
o	"Copy Address" button
o	Network selector (Cardano mainnet/testnet)
o	Warning text: "Only send ADA/USDM to this address"
o	Recent deposits list
30.	Withdraw Screen 
o	Balance display (top)
o	Recipient address input
o	Amount input (with max button)
o	Network fee estimate
o	Total amount (amount + fee)
o	"Review Withdrawal" button
o	Recent recipients list
31.	Transaction Detail 
o	Back button
o	Transaction type (large icon)
o	Amount (large, colored: green for in, red for out)
o	Status badge (Confirmed, Pending, Failed)
o	Timestamp
o	From/To addresses
o	Transaction hash
o	Block number
o	Network fee
o	"View on Explorer" button
32.	Payment Confirmation Modal 
o	Transaction summary
o	Amount
o	Recipient
o	Fee
o	Total
o	"Confirm" and "Cancel" buttons
o	Password/biometric authentication prompt
33.	Transaction Success/Failure 
o	Success: Checkmark animation, "Transaction Successful", tx hash, "Done" button
o	Failure: Error icon, "Transaction Failed", error message, "Try Again" button

PROFILE & SETTINGS (8 screens)
34.	Profile Screen 
o	Avatar (large, with edit button)
o	Name
o	Email
o	DID (truncated, copy button)
o	Wallet address (truncated, copy button)
o	Edit profile button
o	Stats cards: Credentials verified, Total spent, Member since
35.	Edit Profile 
o	Avatar upload (tap to change)
o	Name input
o	Email input
o	Phone input (optional)
o	Bio textarea
o	"Save Changes" button
o	"Cancel" button
36.	Security Settings 
o	Change password section 
	Current password input
	New password input
	Confirm password input
	"Update Password" button
o	Two-factor authentication (2FA) 
	Toggle switch
	"Setup 2FA" button (if disabled)
o	Active sessions list 
	Device, location, last active
	"Sign Out" button per session
o	Connected wallets list 
	Wallet name, address (truncated)
	"Disconnect" button
o	Backup seed phrase button
37.	2FA Setup 
o	Step 1: Scan QR code with authenticator app
o	Step 2: Enter 6-digit code to verify
o	Backup codes (list of 10 codes)
o	"Download Codes" button
o	"Complete Setup" button
38.	Notification Preferences 
o	Email notifications section 
	Toggle switches for: 
	Verification complete
	Payment received
	New messages
	Marketing emails
o	Push notifications section 
	Same toggles
o	SMS notifications section (if enabled)
o	"Save Preferences" button
39.	Privacy Settings 
o	Profile visibility (Public, Private)
o	Data sharing preferences 
	Share analytics (toggle)
	Share with partners (toggle)
o	Cookie preferences
o	Download my data button (GDPR)
o	Delete account button (red, dangerous)
40.	Language & Region 
o	Language selector (dropdown)
o	Date format (MM/DD/YYYY, DD/MM/YYYY, etc.)
o	Time format (12h, 24h)
o	Currency (USD, EUR, NGN, etc.)
o	"Save" button
41.	About 
o	App version
o	Terms of Service link
o	Privacy Policy link
o	Licenses link
o	"Rate App" button
o	"Share App" button
o	Social media links

ADDITIONAL SCREENS (7 screens)
42.	QR Scanner 
o	Camera viewfinder (fullscreen)
o	Scanning frame (center)
o	"Scan QR code to verify credential" text
o	Flash toggle button
o	Close button
o	Scan success animation → redirect to verification
43.	Camera Capture (Document) 
o	Camera viewfinder (fullscreen)
o	Document frame overlay (passport shape)
o	Guide text: "Align document within frame"
o	Capture button (large, center bottom)
o	Flash toggle
o	Switch camera button (front/back)
o	Close button
44.	Loading States 
o	Skeleton screens for: 
	Dashboard loading
	Credential list loading
	Verifier list loading
	Transaction history loading
o	Full-screen loaders with: 
	Animated spinner
	Loading message ("Processing document...", "Verifying credential...", etc.)
45.	Error States 
o	Network error: Illustration, "No internet connection", "Retry" button
o	Server error: Illustration, "Something went wrong", "Try again" button
o	Not found: Illustration, "Credential not found", "Go Back" button
o	Permission denied: Illustration, "Camera permission required", "Open Settings" button
46.	Empty States 
o	No credentials: Illustration, "No credentials yet", "Upload your first credential" button
o	No transactions: Illustration, "No transactions yet", "Make your first transaction" button
o	No notifications: Illustration, "No new notifications"
o	No search results: Illustration, "No results found", "Try different keywords"
47.	Success Confirmations 
o	Credential uploaded: Checkmark animation, "Document submitted!", "View Status" button
o	Payment successful: Checkmark, "Payment sent!", Transaction details, "Done" button
o	Credential shared: Checkmark, "Credential shared!", QR code, "Done" button
48.	Biometric Authentication 
o	Face ID prompt: Face icon, "Authenticate with Face ID" text
o	Fingerprint prompt: Fingerprint icon, "Touch sensor to authenticate"
o	Success/failure states

C. ONBOARDING/TUTORIAL OVERLAYS (5 screens)
49.	First-time Dashboard Tour 
o	Spotlight on key features with tooltips: 
	"This is your dashboard"
	"Upload credentials here"
	"Check your wallet balance"
	"Browse verifiers here"
o	Skip tour button
o	Next/Previous buttons
o	Progress dots
50.	First Upload Tutorial 
o	Step-by-step guide overlay on upload flow
o	Tooltips explaining each step
o	"Got it" buttons
51.	First Verification Request Tutorial 
o	Guide through selecting verifier
o	Explain pricing and timing
o	Payment process walkthrough
52.	Wallet Setup Guide 
o	Connect wallet walkthrough
o	Explain wallet balance
o	Show how to deposit funds
53.	Share Credential Tutorial 
o	Explain QR code sharing
o	Time-limited access explanation
o	Privacy benefits

TOTAL MOBILE APP SCREENS: 53+

PART 2: WEB DASHBOARDS

DASHBOARD 1: USER DASHBOARD (25 pages)
AUTHENTICATION (5 pages)
1.	Landing Page (Marketing) 
o	Hero section (headline, subheadline, CTA)
o	Features section (3-4 key features with icons)
o	How it works (3-step process)
o	Testimonials
o	Pricing cards
o	FAQ
o	Footer (links, social media)
2.	Login Page 
o	Centered glass card (600px)
o	Verza logo
o	"Connect Wallet" button (primary)
o	Divider "or"
o	Email input
o	Password input
o	"Forgot password?" link
o	"Sign In" button
o	"Don't have account? Sign Up" link
o	Animated background gradient
3.	Sign Up Page 
o	Similar layout to login
o	Email, password, confirm password inputs
o	Terms & Privacy checkbox
o	"Create Account" button
o	"Already have account? Sign In" link
4.	Forgot Password 
o	Email input
o	"Send Reset Link" button
o	"Back to Login" link
o	Success message: "Check your email"
5.	Reset Password 
o	New password input
o	Confirm password input
o	Password strength indicator
o	"Reset Password" button
o	Success: Redirect to login

MAIN DASHBOARD (20 pages)
6.	Dashboard Home 
o	Sidebar (left, 256px, collapsible)
o	Topbar (64px, sticky with search, notifications, user menu)
o	Main content: 
	Stats cards (4 across): Total Credentials, Verified, Pending, Wallet Balance
	Charts: Verifications over time (line chart)
	Recent activity feed (right sidebar or bottom section)
	Quick actions (Upload, Request Verification, View Wallet)
7.	Credentials List Page 
o	Filter sidebar (left): Type, Status, Date range
o	Tabs: All, Verified, Pending, Expired
o	View switcher: Grid / List
o	Credential cards (grid): 
	Type icon, status badge, issuer, dates
	Hover: Actions menu (View, Share, Download)
o	Pagination or infinite scroll
o	"Upload New" button (top right)
o	Search bar
8.	Credential Detail Page 
o	Breadcrumbs: Credentials > Passport > Detail
o	Left column (40%): 
	Document preview (blurred/secure)
	Zoom/rotate controls
o	Right column (60%): 
	Credential info (type, status, issuer, dates, DID)
	Blockchain proof section (tx hash, timestamp, block)
	Action buttons: Share, Generate ZK Proof, Download, Revoke
o	Bottom section: 
	Share history (table)
	Activity log (timeline)
9.	Upload Credential - Multi-step Form 
o	Progress stepper (top): Type → Upload → Review → Submit
o	Step 1: Select credential type (card grid)
o	Step 2: Upload document (drag-drop area)
o	Step 3: AI pre-screening results
o	Step 4: Review details form
o	"Back" and "Next" navigation
o	Success: Redirect to verification status
10.	Request Verification Page 
o	Step 1: Select credential (from user's list)
o	Step 2: Browse verifier marketplace 
	Filter panel (left): Price, rating, location
	Verifier cards (grid): Photo, name, rating, price, time, specializations
	"Select" button per verifier
o	Step 3: Confirm and pay 
	Summary card: Document, verifier, price breakdown
	Payment method selector
	"Confirm & Pay" button
11.	Verification Status Page 
o	Large progress tracker (horizontal stepper)
o	Current status card (center): 
	Status message
	Verifier info
	Estimated completion time
	Progress bar
o	Timeline (left sidebar): All events with timestamps
o	Action buttons: Chat with verifier, Cancel request
12.	Marketplace Page 
o	Search bar (top)
o	Filter panel (left sidebar): 
	Credential type (checkboxes)
	Price range (slider)
	Rating (star selector)
	Location (dropdown)
o	Sort dropdown (top right): Rating, Price, Speed
o	Verifier cards (grid, 3-4 across): 
	Photo, name, rating, review count, price, avg time
	"View Profile" or "Request Verification" button
o	Pagination
13.	Verifier Profile Page (Modal or Full Page) 
o	Header: Photo, name, rating, review count
o	Stats: Total verifications, success rate, avg time
o	About section: Bio, specializations
o	Certifications (list with icons)
o	Reviews section (paginated list)
o	"Request Verification" button (sticky)
14.	Share Credential Page/Modal 
o	Credential preview (top)
o	QR code (large, center)
o	Share link input with copy button
o	Settings: 
	Expiry date/time picker
	Permissions dropdown (View only, One-time, etc.)
	Purpose input (optional)
o	"Generate Share" button
o	Active shares table below: 
	Columns: Recipient, Shared on, Expires, Status, Actions (Revoke)
15.	Generate ZK Proof Page/Modal 
o	Credential selector (dropdown)
o	Proof type tabs: Age, Income, Citizenship, Custom
o	Parameter inputs (based on type): 
	Age proof: "Prove age > [X]"
	Income proof: "Prove income > [X]"
	Citizenship: "Prove citizenship in [country list]"
o	Privacy explanation: "This will prove [X] without revealing [Y]"
o	"Generate Proof" button
o	Result: 
	Proof hash
	QR code
	Copy/Share buttons
	"View on Blockchain" link
16.	Wallet Page 
o	Balance cards (top, 3 across): ADA, USDM, VERZA
o	Total value in USD (large, center)
o	Action buttons: Deposit, Withdraw, Swap
o	Transaction history table: 
	Columns: Type, Date, Amount, Status, Actions (View)
	Filter/Search/Export
	Pagination
17.	Deposit Page 
o	Wallet address (large, monospace, with copy button)
o	QR code (center)
o	Network selector (Cardano mainnet/testnet)
o	Instructions: "Send ADA/USDM to this address"
o	Recent deposits table
18.	Withdraw Page 
o	Form: 
	Balance display (top)
	Recipient address input
	Amount input (with max button)
	Network fee estimate
	Total (amount + fee)
o	"Review Withdrawal" button
o	Recent recipients list (clickable to auto-fill)
19.	Transaction Detail Page/Modal 
o	Transaction type icon (large)
o	Amount (large, colored)
o	Status badge
o	Details: 
	Timestamp
	From/To addresses
	Transaction hash
	Block number
	Network fee
o	"View on Explorer" button
20.	Notifications Page 
o	Filter tabs: All, Unread, Verification, Payments, System
o	Notification list (grouped by date): 
	Each: Icon, message, timestamp, mark as read
o	Mark all as read button
o	Clear all button
21.	Settings - Profile Tab 
o	Form: 
	Avatar upload (with preview)
	Name input
	Email input
	Phone input
	Bio textarea
o	"Save Changes" button
22.	Settings - Security Tab 
o	Change password section (collapsible)
o	2FA section: 
	Status (enabled/disabled)
	"Setup 2FA" or "Disable 2FA" button
	QR code and backup codes (if setting up)
o	Active sessions table: 
	Device, location, last active, "Sign Out" button
o	Connected wallets list: 
	Wallet name, address, "Disconnect" button
23.	Settings - Notifications Tab 
o	Email notifications section (toggles)
o	Push notifications section (toggles)
o	SMS notifications section (toggles)
o	"Save Preferences" button
24.	Settings - Privacy Tab 
o	Data sharing preferences (toggles)
o	Cookie preferences
o	"Download My Data" button
o	"Delete Account" button (red, with confirmation modal)
25.	Settings - Billing Tab (if subscriptions) 
o	Current plan card
o	Usage this month (progress bar)
o	Payment methods section: 
	Credit cards (list with delete button)
	"Add Payment Method" button
o	Billing history table (downloadable invoices)

DASHBOARD 2: VERIFIER DASHBOARD (20 pages)
1.	Onboarding Flow (Multi-step) 
o	Step 1: Welcome screen
o	Step 2: Create DID
o	Step 3: Upload professional credentials
o	Step 4: Select credential types (schemas)
o	Step 5: Set pricing per type
o	Step 6: Stake VERZA tokens
o	Step 7: Review & submit
o	Success: Redirect to pending approval
2.	Dashboard Home 
o	Sidebar navigation
o	Stats cards: Total earnings, Reputation score, Active jobs, Completed jobs
o	Earnings chart (line chart over time)
o	Active jobs list (quick view)
o	Recent completions
o	Quick actions: Browse Jobs, View Analytics
3.	Job Board Page 
o	Filter panel (left): 
	Credential type
	Price range
	Urgency (toggle: Urgent only)
	Location
o	Sort dropdown: Newest, Highest paying, Urgent
o	Job cards (grid): 
	Credential type icon
	Price
	Urgency badge
	Deadline
	"View Details" button
o	Pagination
4.	Job Detail Page 
o	Left column (50%): 
	Requester info (anonymized if needed)
	Credential type
	Document preview (thumbnail)
	AI fraud risk assessment (card): 
	Risk score (0-100)
	Flagged issues (if any)
o	Right column (50%): 
	Payment: Amount, deadline
	Estimated time
	Requirements/checklist
	Action buttons: "Accept Job" (green, large), "Decline"
5.	Active Jobs Page 
o	Tabs: In Progress, Pending Review, Overdue
o	Table view: 
	Columns: Credential type, Requester, Deadline, Status, Progress, Actions
	Actions: "Review Document", "Mark Complete", "Request Extension"
o	Filters: Date, Type, Status
6.	Document Review Workspace 
o	Full-screen or split layout
o	Left panel (60%): 
	Document viewer (zoomable, rotatable)
	Tools: Zoom in/out, rotate, enhance, fullscreen
o	Right panel (40%): 
	AI fraud detection results: 
	Security features detected (checkmarks)
	Red flags (warnings)
	Overall score
	Verification checklist (checkboxes): 
	Expiry date valid
	Photo matches
	Hologram visible
	MRZ readable
	etc.
	Notes textarea
	Decision buttons: "Approve & Sign", "Reject" (with reason)
7.	Issue Credential Page 
o	Credential information form (pre-filled from document): 
	Document number
	Issue date
	Expiry date
	Issuing authority
o	Digital signature preview
o	Blockchain anchoring info
o	"Issue Credential & Complete" button (green, large)
8.	Completed Jobs Page 
o	Table view: 
	Columns: Date, Credential type, Requester, Earnings, Rating received, Actions
	Actions: "View Details", "Download Receipt"
o	Filters: Date range, Type, Rating
o	Export to CSV button
o	Total earnings summary (top)
9.	Earnings Page 
o	Summary cards: Total earnings, This month, Pending (in escrow), Available to withdraw
o	Earnings chart (bar chart by month)
o	Breakdown by credential type (pie chart)
o	Recent payouts table
o	"Withdraw Earnings" button
o	Export financial report
10.	Withdraw Earnings Page 
o	Available balance (large)
o	Withdraw to wallet address input
o	Amount input (with max button)
o	Network fee estimate
o	Total received
o	"Confirm Withdrawal" button
o	Withdrawal history table
11.	Reputation Dashboard 
o	Overall reputation score (large, center)
o	Score breakdown (cards): 
	Accuracy score
	Speed score
	Communication score
	Professionalism score
o	Chart: Reputation trend over time
o	User ratings distribution (5-star bar chart)
o	Recent reviews list (with user ratings and comments)
o	Improvement suggestions (AI-generated)
12.	Reviews Page 
o	Filter: Rating (all, 5-star, 4-star, etc.)
o	Review list (cards): 
	User avatar, name (anonymized option)
	Rating stars
	Date
	Comment
	"Reply" button (optional)
o	Pagination
13.	Analytics Page 
o	Date range selector (top right)
o	KPI cards: Total jobs, Completion rate, Avg. completion time, Avg. rating
o	Charts: 
	Jobs completed over time (line)
	Jobs by credential type (pie)
	Earnings trend (bar)
	Peak activity hours (heatmap)
o	Benchmarking: Compare your stats vs. platform average
14.	Profile Settings 
o	Public profile editor: 
	Photo upload
	Name, bio
	Specializations (multi-select)
	Certifications (upload documents)
o	Pricing section: 
	Set price per credential type (table)
o	Availability schedule: 
	Calendar view or toggle (available/unavailable)
o	Auto-accept settings: 
	Toggle: Auto-accept jobs matching criteria
	Criteria: Price above X, specific types
15.	Staking Page 
o	Current stake amount (large)
o	Stake requirement for your tier
o	Benefits of higher stake (list)
o	"Stake More Tokens" button → form: 
	Amount input
	Confirm button
o	"Unstake Tokens" button (with cooldown period warning)
o	Staking history table
o	Penalties/slashing history (if any)
16.	Notifications Page 
o	Same structure as user dashboard
17.	Settings - Account 
o	Profile info
o	Email, phone
o	Password change
18.	Settings - Security 
o	2FA setup
o	Active sessions
o	Connected wallets
19.	Settings - Notifications 
o	Job alerts (email, push)
o	Payment notifications
o	Review notifications
20.	Help & Support 
o	FAQ for verifiers
o	Contact support
o	Community forum link

DASHBOARD 3: ENTERPRISE DASHBOARD (18 pages)
1.	Dashboard Home 
o	Stats cards: API calls this month, Verifications completed, Cost savings, Active team members
o	Usage chart: Verifications over time
o	Cost analysis chart: Spent vs. traditional KYC
o	Recent verifications table (quick view)
o	Quick actions: Bulk Upload, API Management, View Reports
2.	Bulk Verification Page 
o	Upload section: 
	Drag-drop CSV/Excel file
	Template download link
	"Upload File" button
o	Mapping section (after upload): 
	Map CSV columns to Verza fields (dropdowns)
	Preview table (first 10 rows)
	"Start Processing" button
o	Processing: 
	Progress bar (X of Y processed)
	Real-time status updates per row
o	Results: 
	Summary: Success count, Failed count
	Results table: Row, Status, Credential ID, Error (if any)
	"Download Results CSV" button
3.	Verification Requests Page 
o	Filter panel: Date range, Status, Type, Team member
o	Tabs: All, Pending, Completed, Faile
Continue
9:13 PM
d
•	Table view: 
o	Columns: ID, Type, Date, Status, Assigned to, Verifier, Cost, Actions
o	Bulk actions: Select multiple, Export selected, Cancel selected
o	Actions: View details, Download proof, Re-verify
•	Pagination
•	Export to CSV/Excel button (top right)
•	Stats summary (top): Total, Success rate, Avg. cost, Avg. time
4.	Verification Detail Page 
o	Breadcrumbs: Verifications > [ID] > Detail
o	Overview section: 
	Request ID, Type, Status, Date submitted, Date completed
	Requester (team member), Verifier name
o	Credential information: 
	Document type, Extracted data
	Verification result (Pass/Fail)
o	Blockchain proof: 
	Midnight transaction hash
	Cardano escrow transaction hash
	Timestamp, Block number
	"View on Explorer" buttons
o	Cost breakdown: 
	Verifier fee, Platform fee, Total
o	Activity timeline (left sidebar)
o	Actions: Download proof PDF, Re-verify, Export data
5.	API Management Page 
o	API keys section: 
	Table: Key name, Created date, Last used, Status, Actions
	Actions: Copy key, Regenerate, Revoke
	"Create New API Key" button
o	API documentation link (prominent CTA)
o	Usage statistics: 
	Requests this month (chart)
	Rate limit status (progress bar)
	Error rate (chart)
o	Webhook configuration: 
	Webhook URL input
	Secret key
	Events to subscribe (checkboxes)
	Test webhook button
o	Sandbox environment: 
	Toggle: Production / Sandbox
	Sandbox API key
	"Try in API Playground" link
6.	API Documentation Page (Embedded or External) 
o	Navigation sidebar: Endpoints grouped by category
o	Main content: 
	Endpoint details (method, path, description)
	Request parameters (table)
	Request example (code snippet with language tabs)
	Response example (JSON)
	Error codes (table)
o	Search bar (top)
o	"Try It" interactive API tester
7.	Team Management Page 
o	"Invite Team Member" button (top right)
o	Team members table: 
	Columns: Name, Email, Role, Status, Last active, Actions
	Roles: Admin, Manager, Member
	Actions: Edit role, View activity, Remove
o	Pending invitations section (separate table)
o	Filters: Role, Status (Active, Inactive)
8.	Invite Team Member Modal/Page 
o	Form: 
	Email input (or multiple emails)
	Role selector (dropdown with descriptions)
	Permissions checklist: 
	View verifications
	Request verifications
	Bulk upload
	API access
	Billing access
	Team management
	"Send Invitation" button
9.	Team Member Detail Page 
o	Header: Photo, name, email, role
o	Edit role/permissions section
o	Activity log (table): 
	Date, Action, Details
o	Verifications requested (table)
o	"Remove from Team" button (bottom, red)
10.	Compliance Reports Page 
o	Report types (cards or dropdown): 
	GDPR Compliance Report
	Audit Trail Report
	Verification Summary Report
	Cost Analysis Report
	Custom Report
o	Generate report form: 
	Date range picker
	Filters (verification type, status, team member)
	Format selector (PDF, CSV, Excel)
	"Generate Report" button
o	Recent reports (table): 
	Name, Generated date, Format, Size, Actions (Download, Delete)
o	Scheduled reports section: 
	Frequency (Daily, Weekly, Monthly)
	Email recipients
	"Schedule Report" button
11.	Audit Trail Page 
o	Search bar (top)
o	Filters: Date range, User, Action type, Resource
o	Audit log table: 
	Columns: Timestamp, User, Action, Resource, IP address, Details
	Expandable rows for full details
o	Export audit log (CSV)
o	Retention: Display retention period (e.g., "Logs retained for 7 years")
12.	Analytics Dashboard 
o	Date range selector (top right)
o	KPI cards: Total verifications, Success rate, Cost savings, Avg. time
o	Charts: 
	Verifications over time (line chart)
	Verifications by type (pie chart)
	Cost comparison (bar chart: Verza vs. Traditional)
	Top verifiers used (bar chart)
	Fraud detection rate (gauge)
	Verification completion time distribution (histogram)
	Regional breakdown (map or bar chart)
o	Custom report builder: 
	Drag-drop metrics
	Filter options
	Save custom dashboard
13.	Cost Analysis Page 
o	Summary cards: Total spent, Cost per verification, Savings vs. traditional, ROI percentage
o	Cost trend chart (line chart over time)
o	Cost breakdown by: 
	Credential type (pie chart)
	Department/team (bar chart)
	Verifier (table)
o	Comparison table: 
	Traditional KYC cost vs. Verza cost (side-by-side)
o	Export cost report button
14.	Integrations Page 
o	Available integrations (grid of cards): 
	Salesforce, Workday, BambooHR, Greenhouse, SAP, etc.
	Each card: Logo, name, description, "Connect" or "Configure" button
o	Connected integrations: 
	List with status (Active, Error)
	Actions: Configure, Disconnect
o	Webhook integrations: 
	List of configured webhooks
	"Add Webhook" button
o	API integration guide link
15.	Integration Setup Page (e.g., Salesforce) 
o	Step 1: Authorize connection (OAuth)
o	Step 2: Map fields (Verza fields → Salesforce fields)
o	Step 3: Configure sync settings (frequency, direction)
o	Step 4: Test connection
o	Step 5: Activate
o	"Save Integration" button
16.	Billing Page 
o	Current plan card: 
	Plan name (Starter, Business, Enterprise)
	Monthly cost
	Included verifications
	"Upgrade" or "Change Plan" button
o	Usage this month: 
	Verifications used (progress bar: X of Y)
	Overage charges (if any)
	Next billing date
o	Payment methods section: 
	Credit cards list (masked, with delete)
	"Add Payment Method" button
o	Billing history table: 
	Date, Amount, Status, Invoice (download PDF)
o	"View Pricing Plans" link
17.	Pricing Plans Page (if not on billing page) 
o	Comparison table: Features across plans
o	Plans: Starter, Business, Enterprise, Custom
o	Each plan card: 
	Price (per month/year toggle)
	Included verifications
	Features list (checkmarks)
	"Select Plan" or "Current Plan" button
o	FAQ section (bottom)
o	"Contact Sales" button (for Enterprise)
18.	Settings - Company Profile 
o	Company info: 
	Company name
	Industry dropdown
	Company size
	Website
	Logo upload
o	Billing contact: 
	Name, Email, Phone
o	"Save Changes" button

DASHBOARD 4: ADMIN DASHBOARD (22 pages)
1.	Admin Dashboard Home 
o	Platform-wide stats (large cards): 
	Total users
	Total verifications
	Total revenue
	Active verifiers
o	System health indicators: 
	API uptime (green/yellow/red)
	Blockchain sync status
	Database health
	Queue depth
o	Charts: 
	User growth (line chart)
	Daily verifications (bar chart)
	Revenue trend (line chart)
o	Recent alerts (critical issues)
o	Quick actions: Moderate content, Resolve disputes, View reports
2.	User Management Page 
o	Search bar (by email, DID, name)
o	Filters: User type (All, Regular, Verifier, Enterprise), Status (Active, Suspended, Banned)
o	Users table: 
	Columns: Photo, Name, Email, DID, Type, Status, Joined date, Last active, Actions
	Actions: View profile, Edit, Suspend, Ban, Delete
o	Pagination
o	Bulk actions: Export selected, Send notification
3.	User Detail Page 
o	Header: Photo, name, email, DID (full), status badge
o	Tabs: 
	Overview: Basic info, account stats (credentials, verifications, spent)
	Activity: Activity log (table with timestamps)
	Credentials: List of user's credentials
	Transactions: Payment history
	Notes: Admin notes (textarea, save button)
o	Actions (top right): Edit user, Suspend account, Ban account, Delete account, Reset password, Impersonate (dev only)
4.	Verifier Management Page 
o	Tabs: All, Pending Approval, Active, Suspended
o	Search and filters
o	Verifiers table: 
	Columns: Photo, Name, DID, Reputation, Total jobs, Success rate, Stake, Status, Actions
	Actions: View profile, Approve (if pending), Suspend, Slash stake, Deactivate
o	Pending approval counter (badge)
5.	Verifier Detail Page 
o	Header: Photo, name, DID, reputation score, status
o	Tabs: 
	Overview: Bio, specializations, certifications
	Performance: Stats (jobs completed, success rate, avg. time, ratings)
	Jobs: List of completed jobs (table)
	Reviews: User reviews received
	Stake: Stake amount, history, slashing history
	Notes: Admin notes
o	Actions: Approve (if pending), Reject (if pending), Suspend, Slash stake, Deactivate
6.	Approve/Reject Verifier Modal 
o	Verifier info summary
o	Uploaded credentials (view/download)
o	Background check results
o	Decision: 
	Radio buttons: Approve, Reject
	Rejection reason (if reject, textarea)
o	"Submit Decision" button
7.	Slash Stake Modal 
o	Verifier name
o	Current stake amount
o	Slash amount input
o	Reason (dropdown + textarea)
o	Warning: "This action cannot be undone"
o	"Confirm Slash" button
8.	Credential Management Page 
o	Search bar (by credential ID, user, type)
o	Filters: Type, Status, Date range
o	Credentials table: 
	Columns: ID, Type, Owner, Status, Verifier, Date, Midnight TX, Actions
	Actions: View details, Flag as suspicious, Revoke (admin override)
o	Flagged credentials section (separate table or filter)
9.	Credential Detail (Admin View) 
o	Full credential information
o	Document preview (if accessible)
o	Verification history
o	Blockchain proof
o	AI fraud detection results (if available)
o	Admin actions: Flag, Revoke, Add note
o	Activity timeline
10.	Disputes Page 
o	Tabs: Open, In Review, Resolved
o	Disputes table: 
	Columns: Dispute ID, Type, Parties, Filed date, Status, Assigned to, Actions
	Actions: View details, Assign to me, Resolve
o	Filters: Date, Type, Status
11.	Dispute Detail Page 
o	Dispute summary: 
	Dispute ID, Type, Status
	Filed by (requester or verifier)
	Against (verifier or requester)
	Filed date
o	Dispute description (from filer)
o	Evidence section: 
	Uploaded files (if any)
	Chat history (if available)
	Transaction details
o	Verdict section: 
	Resolution options (radio): 
	Full refund to requester
	Full payment to verifier
	Partial refund (specify amount)
	Re-verification required
	Reasoning (textarea)
o	"Submit Resolution" button
o	Activity timeline (left sidebar)
12.	Governance Page 
o	Active proposals (table): 
	Columns: Proposal ID, Title, Type, Proposer, Votes for, Votes against, Status, End date, Actions
	Actions: View details, Execute (if passed)
o	"Create Proposal" button (admin only)
o	Tabs: Active, Passed, Rejected, Executed
o	Voting results chart (for each proposal)
13.	Create Proposal Page 
o	Form: 
	Proposal type (dropdown): 
	Fee adjustment
	Schema addition
	Parameter change
	Treasury allocation
	Emergency action
	Title input
	Description textarea
	Parameters (dynamic based on type): 
	e.g., for fee adjustment: New fee percentage input
	Voting duration (days)
o	"Submit Proposal" button
o	Preview of proposal on blockchain
14.	Proposal Detail Page 
o	Proposal information (title, description, proposer, dates)
o	Current vote count (cards): For, Against, Abstain
o	Voting chart (bar or pie)
o	Recent votes (table): Voter, Vote, Voting power, Timestamp
o	Actions (if passed and not executed): "Execute Proposal" button
o	Discussion section (comments, optional)
15.	Financial Overview Page 
o	Summary cards: Total revenue, Monthly recurring revenue, Escrow balance, Treasury balance
o	Revenue breakdown: 
	By source (pie chart): Transaction fees, Subscriptions, Premium features
	By region (bar chart or map)
	Trend over time (line chart)
o	Escrow management: 
	Total locked in escrows
	Active escrows (count)
	Disputed escrows (count)
o	Payouts: 
	Total paid to verifiers
	Pending payouts
o	Treasury: 
	VERZA token balance
	Treasury transactions (table)
16.	Revenue Drill-Down Page 
o	Date range selector
o	Revenue metrics: 
	Total revenue, Growth rate, Churn rate
o	Charts: 
	Daily/monthly revenue (line)
	Revenue by customer type (pie): Regular, Verifier, Enterprise
	Top revenue-generating enterprises (table)
	Average revenue per user (ARPU) trend
o	Export financial report (PDF/CSV)
17.	System Monitoring Page 
o	Service status grid: 
	Each service: Name, Status (green/yellow/red), Uptime %, Response time
	Services: API Gateway, Credential Service, Verifier Service, AI Service, Blockchain Services, Database, Cache, Message Queue
o	Blockchain sync status: 
	Midnight: Current block, Synced (Yes/No), Last event timestamp
	Cardano: Current block, Synced (Yes/No), Last event timestamp
o	System metrics (real-time or near-real-time): 
	API requests per minute (chart)
	Error rate (chart)
	Database query performance (chart)
	Queue depth (Kafka, RabbitMQ)
o	Alerts section: 
	Critical alerts (red)
	Warnings (yellow)
	"Acknowledge" buttons
o	Link to Grafana dashboards
18.	Error Logs Page 
o	Search bar (by error message, service, user)
o	Filters: Date range, Service, Severity (Critical, Error, Warning)
o	Error log table: 
	Columns: Timestamp, Service, Severity, Error message, User (if applicable), Stack trace (collapsible), Actions
	Actions: View full details, Mark as resolved, Create ticket
o	Pagination
o	Export logs (CSV)
o	Link to Sentry for detailed error tracking
19.	Fraud Detection Page 
o	AI fraud alerts (table): 
	Columns: Alert ID, Document type, Risk score, User, Verifier (if assigned), Date, Status, Actions
	Actions: View details, Approve, Reject, Flag user/verifier
o	Filters: Date, Risk score range, Status
o	Flagged documents section
o	Suspicious patterns section: 
	Multiple uploads from same IP
	Repeated rejections by verifiers
	Unusual activity patterns
o	Charts: 
	Fraud detection rate over time
	Fraud by document type
	False positive rate
20.	Analytics & Reports Page 
o	Pre-built reports (cards): 
	User growth report
	Verification trends report
	Revenue report
	Verifier performance report
	Fraud detection report
	Each card: "Generate" button, last generated date
o	Custom report builder: 
	Drag-drop metrics and dimensions
	Date range selector
	Visualization type (table, line, bar, pie)
	"Generate Report" button
o	Saved reports section (table with load/delete)
21.	Platform Settings Page 
o	Tabs: 
	General: Platform name, logo, support email
	Fees: Transaction fee %, Platform fee for escrow, Enterprise subscription pricing
	Limits: Minimum stake for verifiers, Max file upload size, Rate limits
	Features: Feature flags (toggles for enabling/disabling features)
	Verification: Default verification deadline, Auto-release escrow after X hours
	Notifications: Email templates (edit), SMS provider settings
o	"Save Changes" button per tab
22.	Admin Users Page 
o	List of admin users (table): 
	Name, Email, Role (Super Admin, Admin, Moderator), Status, Last login
	Actions: Edit role, Deactivate, Delete
o	"Invite Admin" button
o	Activity log for admin actions (separate section or page)

ADDITIONAL SHARED COMPONENTS/PAGES (Both Mobile & Web)
ERROR PAGES (4 pages)
1.	404 Not Found 
o	Illustration (404 graphic or animation)
o	"Page not found" heading
o	"The page you're looking for doesn't exist or has been moved"
o	"Go to Dashboard" button
o	"Report Issue" link
2.	500 Server Error 
o	Illustration (server error graphic)
o	"Something went wrong" heading
o	"Our team has been notified. Please try again later."
o	Error ID (for support reference)
o	"Try Again" button
o	"Contact Support" button
3.	403 Forbidden 
o	Illustration (lock icon)
o	"Access Denied" heading
o	"You don't have permission to access this resource"
o	"Go Back" button
o	"Contact Admin" button (if applicable)
4.	Maintenance Mode 
o	Illustration (tools/maintenance graphic)
o	"We'll be back soon!" heading
o	"Scheduled maintenance in progress"
o	Estimated completion time
o	"Check Status Page" link

DESIGN DELIVERABLES SUMMARY
MOBILE APP:
•	Total Screens: 53+ unique screens
•	Includes: Authentication (6), Dashboard (5), Credentials (12), Marketplace (4), Wallet (6), Settings (8), Additional (7), Tutorials (5), Error/Empty states (6)
WEB DASHBOARDS:
User Dashboard: 25 pages
•	Authentication (5), Main Dashboard (20)
Verifier Dashboard: 20 pages
•	Onboarding (1), Dashboard pages (19)
Enterprise Dashboard: 18 pages
•	All enterprise-specific features
Admin Dashboard: 22 pages
•	Full platform management and monitoring
Shared Pages: 4 error pages
TOTAL WEB PAGES: 89 unique pages

DESIGN SYSTEM COMPONENTS NEEDED
To support all these pages, the designer must create:
Navigation Components:
1.	Top navigation bar (web)
2.	Sidebar navigation (web) - collapsible
3.	Bottom tab bar (mobile)
4.	Breadcrumbs (web)
5.	Pagination component
6.	Tabs component
Data Display:
7.	Data table (sortable, filterable, selectable)
8.	Credential card (grid and list views)
9.	Verifier card
10.	Stats card with trend indicator
11.	Transaction item (list)
12.	Notification item
13.	Timeline component
14.	Progress stepper (horizontal and vertical)
15.	Charts (line, bar, pie, area, gauge)
16.	Badge/Status indicator
17.	Avatar/User profile display
18.	Empty states (with illustrations)
19.	Loading states (skeleton screens)
Forms & Inputs:
20.	Text input (various states: default, focus, error, disabled)
21.	Textarea
22.	Select dropdown (single and multi-select)
23.	Date/time picker
24.	File upload (drag-drop, progress bar)
25.	Toggle switch
26.	Checkbox
27.	Radio button
28.	Range slider
29.	Search bar with autocomplete
30.	Form validation messages
Buttons & Actions:
31.	Primary button
32.	Secondary button
33.	Ghost/text button
34.	Icon button
35.	Button with loading state
36.	Button group
37.	FAB (Floating Action Button)
38.	Split button (with dropdown)
Feedback & Overlays:
39.	Modal/Dialog (various sizes)
40.	Bottom sheet (mobile)
41.	Drawer/Side panel
42.	Toast notification (success, error, warning, info)
43.	Alert banner
44.	Tooltip
45.	Popover
46.	Confirmation dialog
47.	Loading spinner
48.	Progress bar (linear and circular)
Media & Visual:
49.	Image with placeholder
50.	QR code display/scanner
51.	Document viewer/preview
52.	Video player (if needed)
53.	Icon system (consistent icon set)
54.	Illustrations (empty states, errors, success)
55.	Animations (Framer Motion variants)
Advanced Components:
56.	Calendar/Date range picker
57.	Rich text editor (if needed for notes)
58.	Code snippet display (for API docs)
59.	Command palette (Cmd+K)
60.	Onboarding tour/Spotlight
61.	Rating component (stars)
62.	Wallet connection modal
63.	Transaction confirmation modal
64.	Filter panel/sheet
65.	Map component (if showing verifier locations)

RESPONSIVE BREAKPOINTS
All web pages must be designed for:
•	Desktop: 1920px, 1440px, 1280px
•	Tablet: 1024px, 768px
•	Mobile: 375px, 320px
Mobile app screens for:
•	iOS: iPhone 14 Pro (393 x 852), iPhone SE (375 x 667)
•	Android: Pixel 7 (412 x 915), Small device (360 x 640)

DESIGN FILE ORGANIZATION
Recommended Figma structure:
Verza Design System
├──	 Mobile App
│   ├──  Authentication
│   ├── Dashboard
│   ├──  Credentials
│   ├──  Marketplace
│   ├──  Wallet
│   ├──  Settings
│   └──  Onboarding
├──  Web - User Dashboard
├──  Web - Verifier Dashboard
├──  Web - Enterprise Dashboard
├──  Web - Admin Dashboard
├──  Design System
│   ├── Colors
│   ├── Typography
│   ├── Components
│   ├── Icons
│   ├── Illustrations
│   └── Animations
├──  Layouts & Grids
├──  Dark Mode (if applicable)
└──  Documentation

PROTOTYPING REQUIREMENTS
The designer should create interactive prototypes for:
Critical Flows:
1.	Mobile: Sign up → Upload credential → Select verifier → Payment → Status tracking → Credential received
2.	Mobile: Share credential via QR code
3.	Web (User): Request verification flow
4.	Web (Verifier): Accept job → Review document → Issue credential
5.	Web (Enterprise): Bulk upload CSV → Process → View results
6.	Web (Admin): Resolve dispute flow
Prototype Features:
•	Clickable hotspots
•	Animated transitions (page transitions, modals, loading states)
•	Smart Animate for micro-interactions
•	Component states (hover, active, disabled)
•	Realistic data (not lorem ipsum)

ACCESSIBILITY REQUIREMENTS
All designs must meet WCAG 2.1 AA standards:
•	Color contrast ratios: 4.5:1 minimum for text
•	Focus indicators visible on all interactive elements
•	Touch targets: 44x44px minimum (mobile)
•	Alt text for all images and icons
•	Keyboard navigation support (web)
•	Screen reader friendly structure

ANIMATION SPECIFICATIONS
Document Framer Motion animations for:
•	Page transitions (fade, slide)
•	Card hover effects (lift, glow)
•	Button states (scale, color)
•	Loading states (skeleton, spinner)
•	Success/error confirmations (checkmark, shake)
•	Modal open/close (scale + fade)
•	Drawer slide in/out
•	Toast notifications (slide from top/right)

HANDOFF REQUIREMENTS
The designer should provide:
1.	Figma files with all screens organized
2.	Design system documentation (Storybook or Figma)
3.	Component specifications (spacing, typography, colors)
4.	Interaction specifications (hover states, animations)
5.	Assets export: 
o	Icons (SVG)
o	Illustrations (SVG or PNG)




o	Images (WebP, PNG with @2x @3x)
o	Animations (Lottie JSON if using After Effects)
6.	Developer handoff notes (implementation details)
7.	Accessibility annotations
8.	Prototype links for critical flows

TOTAL DESIGN SCOPE:
•	Mobile: 53+ screens
•	Web: 89+ pages
•	Components: 65+ reusable components
•	Design System: Complete with documentation
•	Prototypes: 6+ critical flow prototypes
•	Responsive: All breakpoints
•	Accessibility: WCAG 2.1 AA compliant

will add more changes later on