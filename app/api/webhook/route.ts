// app/api/webhook/route.ts
import { Webhook } from 'svix';
import { headers } from 'next/headers';
import { NextResponse } from 'next/server';
import { prisma } from '../../../lib/prisma';


export async function POST(req: Request) {
    console.log("✅ Clerk webhook POST received"); 
  const WEBHOOK_SECRET = process.env.CLERK_WEBHOOK_SECRET;

  if (!WEBHOOK_SECRET) {
    return new NextResponse('Webhook secret not found', { status: 400 });
  }

  const payload = await req.text();
  const headerPayload = headers();

  const svix_id = headerPayload.get('svix-id')!;
  const svix_timestamp = headerPayload.get('svix-timestamp')!;
  const svix_signature = headerPayload.get('svix-signature')!;

  const wh = new Webhook(WEBHOOK_SECRET);

  let evt;
  try {
    evt = wh.verify(payload, {
      'svix-id': svix_id,
      'svix-timestamp': svix_timestamp,
      'svix-signature': svix_signature,
    });
  } catch (err) {
    console.error('Webhook verification failed', err);
    return new NextResponse('Invalid signature', { status: 400 });
  }

  const { id, email_addresses, first_name, last_name } = evt.data;

  if (evt.type === 'user.created') {
    try {
      await prisma.user.create({
        data: {
          clerkId: id,
          email: email_addresses[0].email_address,
          firstName: first_name,
          lastName: last_name,
        },
      });
    } catch (err) {
      console.error('Failed to save user to DB:', err);
      return new NextResponse('DB error', { status: 500 });
    }
  }

  return new NextResponse('OK', { status: 200 });
}
