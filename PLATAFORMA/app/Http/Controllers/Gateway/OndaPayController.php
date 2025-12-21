<?php

namespace App\Http\Controllers\Gateway;

use App\Http\Controllers\Controller;

use App\Traits\Gateways\OndaPayTrait;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class OndaPayController extends Controller
{
    use OndaPayTrait;

    /*** @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function callbackMethodPayment(Request $request)
    {
        $data = $request->all();
        DB::table('debug')->insert(['text' => json_encode($request->all())]);

        return response()->json([], 200);
    }

    /*** @param Request $request
     * @return \Illuminate\Http\JsonResponse|void
     */
    public function callbackMethod(Request $request)
    {
        $data = $request->all();

        self::webhookOnda($request);
    }

    /*** @param Request $request
     * @return null
     */
    public function getQRCodePix(Request $request)
    {
        return self::requestQrcodeOnda($request);
    }

    /*** Show the form for creating a new resource.
     */


    /**vc
     * @param $id
     * @return \Illuminate\Http\RedirectResponse|void
     */
}
